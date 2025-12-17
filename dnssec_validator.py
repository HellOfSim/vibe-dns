#!/usr/bin/env python3
# filename: dnssec_validator.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# -----------------------------------------------------------------------------
"""
DNSSEC Validation with configurable modes:
- none:     No validation
- log:      Validate and log results, but never block
- standard: Block BOGUS/INDETERMINATE, allow SECURE/INSECURE
- strict:   Only allow SECURE responses
"""

import asyncio
import time
import hashlib
import struct
from enum import Enum
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass, field

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.rrset
import dns.dnssec
import dns.flags

from utils import get_logger

logger = get_logger("DNSSEC")


class DNSSECStatus(Enum):
    """DNSSEC validation result states"""
    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"
    INDETERMINATE = "indeterminate"
    
    def is_valid_for_mode(self, mode: str) -> bool:
        if mode == "none":
            return True
        elif mode == "log":
            return True
        elif mode == "standard":
            return self in (DNSSECStatus.SECURE, DNSSECStatus.INSECURE)
        elif mode == "strict":
            return self == DNSSECStatus.SECURE
        return False


@dataclass
class DNSSECStats:
    """Statistics for DNSSEC validation"""
    secure_count: int = 0
    insecure_count: int = 0
    bogus_count: int = 0
    indeterminate_count: int = 0
    blocked_count: int = 0
    validation_errors: int = 0
    cache_hits: int = 0
    
    def record(self, status: DNSSECStatus, blocked: bool = False):
        if status == DNSSECStatus.SECURE:
            self.secure_count += 1
        elif status == DNSSECStatus.INSECURE:
            self.insecure_count += 1
        elif status == DNSSECStatus.BOGUS:
            self.bogus_count += 1
        elif status == DNSSECStatus.INDETERMINATE:
            self.indeterminate_count += 1
        if blocked:
            self.blocked_count += 1
    
    def get_stats(self) -> dict:
        total = self.secure_count + self.insecure_count + self.bogus_count + self.indeterminate_count
        return {
            'total_validations': total,
            'secure': self.secure_count,
            'insecure': self.insecure_count,
            'bogus': self.bogus_count,
            'indeterminate': self.indeterminate_count,
            'blocked': self.blocked_count,
            'validation_errors': self.validation_errors,
            'cache_hits': self.cache_hits,
            'secure_rate': f"{(self.secure_count / total * 100):.1f}%" if total > 0 else "0%"
        }


class DNSSECValidator:
    """DNSSEC validation with configurable modes"""
    
    def __init__(self, config: dict, trust_anchors: dict, query_func=None):
        """
        Initialize DNSSEC validator.
        
        Args:
            config: DNSSEC configuration dict
            trust_anchors: Root trust anchors {key_tag: {algorithm, digest_type, digest}}
            query_func: Async function to query DNS (for fetching DNSKEY/DS)
        """
        self.mode = config.get('mode', 'none')
        self.trust_anchors = trust_anchors or {}
        self.query_func = query_func
        
        # Response codes
        self.failure_rcode = self._parse_rcode(config.get('validation_failure_rcode', 'SERVFAIL'))
        self.unsigned_rcode = self._parse_rcode(config.get('unsigned_zone_rcode', 'SERVFAIL'))
        
        # Algorithm filtering
        self.disabled_algorithms = set(config.get('disabled_algorithms', []))
        
        # Caching
        self.cache_enabled = config.get('cache_validated', True)
        self.cache_ttl = config.get('cache_ttl', 300)
        self.validated_keys: Dict[str, Tuple[dns.rrset.RRset, float]] = {}
        self.ds_cache: Dict[str, Tuple[Optional[dns.rrset.RRset], float]] = {}
        self.negative_cache: Dict[str, float] = {}  # zone -> expiry for bogus zones
        
        # Stats
        self.stats = DNSSECStats()
        
        if self.mode != "none":
            logger.info(f"DNSSEC Validator: mode={self.mode}, "
                       f"failure_rcode={dns.rcode.to_text(self.failure_rcode)}, "
                       f"trust_anchors={len(self.trust_anchors)}")
    
    def _parse_rcode(self, rcode_str: str) -> dns.rcode.Rcode:
        rcode_map = {
            'SERVFAIL': dns.rcode.SERVFAIL,
            'REFUSED': dns.rcode.REFUSED,
            'NXDOMAIN': dns.rcode.NXDOMAIN,
            'FORMERR': dns.rcode.FORMERR,
            'NOERROR': dns.rcode.NOERROR,
        }
        return rcode_map.get(rcode_str.upper(), dns.rcode.SERVFAIL)
    
    def set_query_func(self, func):
        """Set the query function for fetching DNSKEY/DS records"""
        self.query_func = func
    
    async def validate_response(
        self,
        response: dns.message.Message,
        qname: str,
        qtype: int,
        req_logger=None
    ) -> Tuple[DNSSECStatus, Optional[dns.message.Message]]:
        """
        Validate DNS response and return (status, response_or_error).
        
        Returns:
            (status, response) - response is modified error response if blocked
        """
        log = req_logger or logger
        
        if self.mode == "none":
            return DNSSECStatus.SECURE, response
        
        # Check negative cache
        qname_norm = qname.lower().rstrip('.') + '.'
        if qname_norm in self.negative_cache:
            if time.time() < self.negative_cache[qname_norm]:
                self.stats.cache_hits += 1
                log.debug(f"DNSSEC: Negative cache hit for {qname}")
                return self._apply_mode(DNSSECStatus.BOGUS, response, qname, log)
        
        try:
            # Check if response has DNSSEC records
            has_rrsig = self._has_rrsig(response)
            
            if not has_rrsig:
                # Check if zone should be signed
                status = await self._check_unsigned_zone(qname_norm, log)
            else:
                # Validate signatures
                status = await self._validate_signatures(response, qname_norm, log)
            
            # Record stats
            self.stats.record(status)
            
            # Apply mode logic
            return self._apply_mode(status, response, qname, log)
            
        except Exception as e:
            self.stats.validation_errors += 1
            log.error(f"DNSSEC: Validation error for {qname}: {e}")
            status = DNSSECStatus.INDETERMINATE
            self.stats.record(status)
            return self._apply_mode(status, response, qname, log)
    
    def _has_rrsig(self, response: dns.message.Message) -> bool:
        """Check if response contains any RRSIG records"""
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    return True
        return False
    
    async def _check_unsigned_zone(self, qname: str, log) -> DNSSECStatus:
        """
        Determine if unsigned response is expected (INSECURE) or wrong (BOGUS).
        Walk up tree looking for DS records.
        """
        if not self.query_func:
            log.debug(f"DNSSEC: No query function, assuming INSECURE for {qname}")
            return DNSSECStatus.INSECURE
        
        # Check parent zones for DS
        zone = qname
        checked = set()
        
        while zone and zone not in checked:
            checked.add(zone)
            parent = self._get_parent_zone(zone)
            
            if not parent:
                # Reached root without finding DS = insecure delegation
                return DNSSECStatus.INSECURE
            
            # Check cache first
            cache_key = f"ds:{zone}"
            if cache_key in self.ds_cache:
                ds_rrset, expiry = self.ds_cache[cache_key]
                if time.time() < expiry:
                    self.stats.cache_hits += 1
                    if ds_rrset:
                        # Has DS = should be signed but isn't
                        log.warning(f"DNSSEC: Zone {zone} has DS but response unsigned")
                        return DNSSECStatus.BOGUS
                    else:
                        # No DS = legitimately unsigned
                        return DNSSECStatus.INSECURE
            
            # Query for DS at parent
            try:
                ds_response = await self._query_ds(zone, log)
                if ds_response:
                    ds_rrset = self._extract_rrset(ds_response, zone, dns.rdatatype.DS)
                    if ds_rrset:
                        # Cache positive
                        ttl = min((rr.ttl for rr in ds_response.answer), default=300)
                        self.ds_cache[cache_key] = (ds_rrset, time.time() + ttl)
                        log.warning(f"DNSSEC: Zone {zone} has DS at parent but response unsigned")
                        return DNSSECStatus.BOGUS
                    else:
                        # No DS in response - check for NSEC/NSEC3 proving non-existence
                        # For now, treat as insecure
                        self.ds_cache[cache_key] = (None, time.time() + 300)
                        return DNSSECStatus.INSECURE
            except Exception as e:
                log.debug(f"DNSSEC: Failed to query DS for {zone}: {e}")
            
            zone = parent
        
        return DNSSECStatus.INSECURE
    
    async def _query_ds(self, zone: str, log) -> Optional[dns.message.Message]:
        """Query for DS record at parent zone"""
        if not self.query_func:
            return None
        
        try:
            # Query with DO bit set
            query = dns.message.make_query(
                dns.name.from_text(zone),
                dns.rdatatype.DS,
                want_dnssec=True
            )
            return await self.query_func(query.to_wire())
        except Exception as e:
            log.debug(f"DNSSEC: DS query failed for {zone}: {e}")
            return None
    
    async def _validate_signatures(
        self,
        response: dns.message.Message,
        qname: str,
        log
    ) -> DNSSECStatus:
        """Validate RRSIG records in response"""
        try:
            # Group RRsets and their RRSIGs
            rrsets_to_validate = []
            rrsigs = {}
            
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    # Index by (name, type_covered)
                    for rdata in rrset:
                        key = (rrset.name, rdata.type_covered)
                        if key not in rrsigs:
                            rrsigs[key] = dns.rrset.RRset(rrset.name, rrset.rdclass, dns.rdatatype.RRSIG)
                        rrsigs[key].add(rdata, rrset.ttl)
                else:
                    rrsets_to_validate.append(rrset)
            
            if not rrsets_to_validate:
                # No data to validate (maybe authority-only response)
                return DNSSECStatus.SECURE
            
            # Validate each RRset
            for rrset in rrsets_to_validate:
                key = (rrset.name, rrset.rdtype)
                rrsig_rrset = rrsigs.get(key)
                
                if not rrsig_rrset:
                    log.warning(f"DNSSEC: Missing RRSIG for {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}")
                    return DNSSECStatus.BOGUS
                
                # Get signer zone
                signer = str(rrsig_rrset[0].signer).lower()
                if not signer.endswith('.'):
                    signer += '.'
                
                # Check algorithm
                for rrsig in rrsig_rrset:
                    if rrsig.algorithm in self.disabled_algorithms:
                        log.warning(f"DNSSEC: Disabled algorithm {rrsig.algorithm} for {qname}")
                        return DNSSECStatus.BOGUS
                
                # Get validated DNSKEY for signer
                dnskey_rrset = await self._get_validated_dnskey(signer, log)
                if not dnskey_rrset:
                    log.warning(f"DNSSEC: Cannot get validated DNSKEY for {signer}")
                    return DNSSECStatus.INDETERMINATE
                
                # Validate signature
                try:
                    keys = {dns.name.from_text(signer): dnskey_rrset}
                    dns.dnssec.validate(rrset, rrsig_rrset, keys)
                    log.debug(f"DNSSEC: Validated {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}")
                except dns.dnssec.ValidationFailure as e:
                    log.warning(f"DNSSEC: Signature validation failed for {rrset.name}: {e}")
                    # Cache negative result
                    self.negative_cache[qname] = time.time() + self.cache_ttl
                    return DNSSECStatus.BOGUS
            
            return DNSSECStatus.SECURE
            
        except Exception as e:
            log.error(f"DNSSEC: Validation error: {e}")
            return DNSSECStatus.INDETERMINATE
    
    async def _get_validated_dnskey(self, zone: str, log) -> Optional[dns.rrset.RRset]:
        """Get DNSKEY for zone, validating chain to trust anchor"""
        # Check cache
        if zone in self.validated_keys:
            dnskey, expiry = self.validated_keys[zone]
            if time.time() < expiry:
                self.stats.cache_hits += 1
                return dnskey
            else:
                del self.validated_keys[zone]
        
        if not self.query_func:
            log.debug(f"DNSSEC: No query function for DNSKEY fetch")
            return None
        
        try:
            # Query DNSKEY with DO bit
            query = dns.message.make_query(
                dns.name.from_text(zone),
                dns.rdatatype.DNSKEY,
                want_dnssec=True
            )
            response_wire = await self.query_func(query.to_wire())
            if not response_wire:
                return None
            
            response = dns.message.from_wire(response_wire)
            dnskey_rrset = self._extract_rrset(response, zone, dns.rdatatype.DNSKEY)
            
            if not dnskey_rrset:
                log.warning(f"DNSSEC: No DNSKEY in response for {zone}")
                return None
            
            # Validate DNSKEY
            if zone == '.' or zone == '':
                # Root zone - validate against trust anchor
                if not self._validate_root_dnskey(dnskey_rrset, log):
                    log.warning(f"DNSSEC: Root DNSKEY validation failed")
                    return None
            else:
                # Non-root - validate against parent DS
                if not await self._validate_dnskey_with_ds(zone, dnskey_rrset, response, log):
                    log.warning(f"DNSSEC: DNSKEY chain validation failed for {zone}")
                    return None
            
            # Cache validated key
            ttl = min((rr.ttl for rr in response.answer), default=300)
            self.validated_keys[zone] = (dnskey_rrset, time.time() + ttl)
            log.debug(f"DNSSEC: Cached validated DNSKEY for {zone}")
            
            return dnskey_rrset
            
        except Exception as e:
            log.error(f"DNSSEC: Failed to get DNSKEY for {zone}: {e}")
            return None
    
    def _validate_root_dnskey(self, dnskey_rrset: dns.rrset.RRset, log) -> bool:
        """Validate root DNSKEY against built-in trust anchors"""
        if not self.trust_anchors:
            log.warning("DNSSEC: No trust anchors configured")
            return False
        
        for rdata in dnskey_rrset:
            # Only check KSKs (SEP flag set)
            if not (rdata.flags & 0x0001):  # SEP flag
                continue
            
            key_tag = dns.dnssec.key_id(rdata)
            
            if key_tag in self.trust_anchors:
                anchor = self.trust_anchors[key_tag]
                
                # Compute DS from DNSKEY
                try:
                    computed_ds = dns.dnssec.make_ds(
                        dns.name.root,
                        rdata,
                        anchor['digest_type']
                    )
                    
                    expected_digest = anchor['digest']
                    if isinstance(expected_digest, str):
                        expected_digest = bytes.fromhex(expected_digest)
                    
                    if computed_ds.digest == expected_digest:
                        log.debug(f"DNSSEC: Root DNSKEY validated (key_tag={key_tag})")
                        return True
                except Exception as e:
                    log.debug(f"DNSSEC: DS computation failed for key_tag={key_tag}: {e}")
        
        log.warning("DNSSEC: No matching trust anchor found for root DNSKEY")
        return False
    
    async def _validate_dnskey_with_ds(
        self,
        zone: str,
        dnskey_rrset: dns.rrset.RRset,
        dnskey_response: dns.message.Message,
        log
    ) -> bool:
        """Validate DNSKEY against DS record from parent"""
        # Get DS from parent
        ds_response = await self._query_ds(zone, log)
        if not ds_response:
            log.debug(f"DNSSEC: No DS available for {zone}")
            return False
        
        ds_rrset = self._extract_rrset(ds_response, zone, dns.rdatatype.DS)
        if not ds_rrset:
            # No DS = unsigned delegation (but we have DNSKEY, so something's wrong)
            log.warning(f"DNSSEC: DNSKEY exists but no DS at parent for {zone}")
            return False
        
        # Find matching DNSKEY for DS
        for ds in ds_rrset:
            for dnskey in dnskey_rrset:
                if not (dnskey.flags & 0x0001):  # Only check KSKs
                    continue
                
                if ds.algorithm != dnskey.algorithm:
                    continue
                
                key_tag = dns.dnssec.key_id(dnskey)
                if ds.key_tag != key_tag:
                    continue
                
                # Compute DS from DNSKEY and compare
                try:
                    computed_ds = dns.dnssec.make_ds(
                        dns.name.from_text(zone),
                        dnskey,
                        ds.digest_type
                    )
                    
                    if computed_ds.digest == ds.digest:
                        log.debug(f"DNSSEC: DNSKEY validated against DS for {zone}")
                        
                        # Now validate DNSKEY RRSIG
                        rrsig_rrset = self._extract_rrset(dnskey_response, zone, dns.rdatatype.RRSIG)
                        if rrsig_rrset:
                            try:
                                keys = {dns.name.from_text(zone): dnskey_rrset}
                                dns.dnssec.validate(dnskey_rrset, rrsig_rrset, keys)
                                return True
                            except dns.dnssec.ValidationFailure as e:
                                log.warning(f"DNSSEC: DNSKEY RRSIG validation failed: {e}")
                        else:
                            # DNSKEY matches DS but no RRSIG - accept for now
                            return True
                except Exception as e:
                    log.debug(f"DNSSEC: DS comparison failed: {e}")
        
        log.warning(f"DNSSEC: No DNSKEY matches DS for {zone}")
        return False
    
    def _extract_rrset(
        self,
        response: dns.message.Message,
        name: str,
        rdtype: int
    ) -> Optional[dns.rrset.RRset]:
        """Extract RRset from response by name and type"""
        name_obj = dns.name.from_text(name) if isinstance(name, str) else name
        
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.name == name_obj and rrset.rdtype == rdtype:
                    return rrset
        return None
    
    def _get_parent_zone(self, zone: str) -> Optional[str]:
        """Get parent zone name"""
        zone = zone.rstrip('.')
        if not zone or zone == '.':
            return None
        
        parts = zone.split('.')
        if len(parts) <= 1:
            return '.'
        
        return '.'.join(parts[1:]) + '.'
    
    def _apply_mode(
        self,
        status: DNSSECStatus,
        response: dns.message.Message,
        qname: str,
        log
    ) -> Tuple[DNSSECStatus, Optional[dns.message.Message]]:
        """Apply mode-specific logic to validation result"""
        
        # Log for all modes except 'none'
        if self.mode != "none":
            if status == DNSSECStatus.SECURE:
                log.debug(f"DNSSEC: ✓ SECURE | {qname}")
            elif status == DNSSECStatus.INSECURE:
                log.debug(f"DNSSEC: ○ INSECURE (unsigned) | {qname}")
            elif status == DNSSECStatus.BOGUS:
                log.warning(f"DNSSEC: ✗ BOGUS (validation failed) | {qname}")
            elif status == DNSSECStatus.INDETERMINATE:
                log.warning(f"DNSSEC: ? INDETERMINATE | {qname}")
        
        # Mode: none - always pass
        if self.mode == "none":
            return status, response
        
        # Mode: log - always pass
        if self.mode == "log":
            return status, response
        
        # Mode: standard - block BOGUS and INDETERMINATE
        if self.mode == "standard":
            if status in (DNSSECStatus.BOGUS, DNSSECStatus.INDETERMINATE):
                log.info(f"DNSSEC: ⛔ BLOCKED (mode=standard) | {qname} | Status: {status.value}")
                self.stats.blocked_count += 1
                return status, self._make_error_response(response, self.failure_rcode)
            
            # Set AD flag for secure responses
            if status == DNSSECStatus.SECURE:
                response.flags |= dns.flags.AD
            
            return status, response
        
        # Mode: strict - only SECURE passes
        if self.mode == "strict":
            if status == DNSSECStatus.SECURE:
                response.flags |= dns.flags.AD
                return status, response
            elif status == DNSSECStatus.INSECURE:
                log.info(f"DNSSEC: ⛔ BLOCKED (mode=strict, unsigned) | {qname}")
                self.stats.blocked_count += 1
                return status, self._make_error_response(response, self.unsigned_rcode)
            else:
                log.info(f"DNSSEC: ⛔ BLOCKED (mode=strict) | {qname} | Status: {status.value}")
                self.stats.blocked_count += 1
                return status, self._make_error_response(response, self.failure_rcode)
        
        return status, response
    
    def _make_error_response(
        self,
        original: dns.message.Message,
        rcode: dns.rcode.Rcode
    ) -> dns.message.Message:
        """Create error response preserving question section"""
        response = dns.message.make_response(original)
        response.set_rcode(rcode)
        response.answer.clear()
        response.authority.clear()
        response.additional.clear()
        return response
    
    def get_stats(self) -> dict:
        """Get validation statistics"""
        return self.stats.get_stats()
    
    def clear_cache(self):
        """Clear all caches"""
        self.validated_keys.clear()
        self.ds_cache.clear()
        self.negative_cache.clear()

