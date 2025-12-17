#!/usr/bin/env python3
# filename: recursive_resolver.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# -----------------------------------------------------------------------------
"""
Iterative/Recursive DNS resolver that walks the DNS tree from root servers.
Supports DNSSEC validation.
"""

import asyncio
import socket
import random
import time
from typing import Optional, Dict, List, Tuple, Set
from dataclasses import dataclass, field

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.rrset

from utils import get_logger
from root_hints import RootHintsManager, TrustAnchorManager
from dnssec_validator import DNSSECValidator, DNSSECStatus

logger = get_logger("Recursive")


@dataclass
class RecursiveStats:
    """Statistics for recursive resolution"""
    queries_total: int = 0
    queries_success: int = 0
    queries_failed: int = 0
    queries_from_cache: int = 0
    referrals_followed: int = 0
    root_queries: int = 0
    avg_chain_length: float = 0.0
    _chain_lengths: List[int] = field(default_factory=list)
    
    def record_query(self, success: bool, chain_length: int = 0, from_cache: bool = False):
        self.queries_total += 1
        if success:
            self.queries_success += 1
        else:
            self.queries_failed += 1
        if from_cache:
            self.queries_from_cache += 1
        if chain_length > 0:
            self._chain_lengths.append(chain_length)
            self.avg_chain_length = sum(self._chain_lengths) / len(self._chain_lengths)
    
    def get_stats(self) -> dict:
        return {
            'queries_total': self.queries_total,
            'queries_success': self.queries_success,
            'queries_failed': self.queries_failed,
            'queries_from_cache': self.queries_from_cache,
            'referrals_followed': self.referrals_followed,
            'root_queries': self.root_queries,
            'avg_chain_length': f"{self.avg_chain_length:.2f}",
            'success_rate': f"{(self.queries_success / self.queries_total * 100):.1f}%" if self.queries_total > 0 else "0%"
        }


class NSCache:
    """Cache for nameserver records discovered during resolution"""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 86400):
        self.cache: Dict[str, Tuple[List[Tuple[str, List[str]]], float]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
    
    def get(self, zone: str) -> Optional[List[Tuple[str, List[str]]]]:
        """Get cached NS records for zone: [(ns_name, [ip1, ip2, ...]), ...]"""
        zone = zone.lower().rstrip('.') + '.'
        if zone in self.cache:
            ns_list, expiry = self.cache[zone]
            if time.time() < expiry:
                return ns_list
            del self.cache[zone]
        return None
    
    def put(self, zone: str, ns_records: List[Tuple[str, List[str]]], ttl: int = None):
        """Cache NS records for zone"""
        if self.max_size <= 0:
            return
        
        zone = zone.lower().rstrip('.') + '.'
        ttl = ttl or self.default_ttl
        
        # LRU eviction
        if len(self.cache) >= self.max_size and zone not in self.cache:
            oldest = min(self.cache.items(), key=lambda x: x[1][1])
            del self.cache[oldest[0]]
        
        self.cache[zone] = (ns_records, time.time() + ttl)
    
    def clear(self):
        self.cache.clear()


class RecursiveResolver:
    """
    Iterative DNS resolver that walks from root to authoritative servers.
    """
    
    MAX_REFERRALS = 20
    MAX_CNAME_CHAIN = 10
    QUERY_TIMEOUT = 5
    
    def __init__(self, config: dict):
        """
        Initialize recursive resolver.
        
        Args:
            config: Recursive resolver configuration
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        
        # Root hints
        root_hints_cfg = self.config.get('root_hints', {})
        self.root_hints = RootHintsManager(root_hints_cfg)
        
        # Trust anchors
        trust_anchors_cfg = self.config.get('trust_anchors', {})
        self.trust_anchor_manager = TrustAnchorManager(trust_anchors_cfg)
        
        # DNSSEC
        dnssec_cfg = self.config.get('dnssec', {})
        self.dnssec_mode = dnssec_cfg.get('mode', 'none')
        self.dnssec_validator: Optional[DNSSECValidator] = None
        
        # Caching
        self.ns_cache = NSCache(
            max_size=self.config.get('ns_cache_size', 10000),
            default_ttl=self.config.get('ns_cache_ttl', 86400)
        )
        
        # Stats
        self.stats = RecursiveStats()
        
        # Query settings
        self.prefer_ipv6 = self.config.get('prefer_ipv6', False)
        self.query_timeout = self.config.get('query_timeout', self.QUERY_TIMEOUT)
    
    async def initialize(self) -> bool:
        """Initialize resolver components"""
        if not self.enabled:
            logger.info("Recursive resolver: DISABLED")
            return True
        
        logger.info("Initializing recursive resolver...")
        
        # Load root hints
        if not await self.root_hints.initialize():
            logger.error("Failed to load root hints")
            return False
        
        # Load trust anchors
        if not await self.trust_anchor_manager.initialize():
            logger.warning("Failed to load trust anchors, DNSSEC disabled")
            self.dnssec_mode = 'none'
        
        # Initialize DNSSEC validator
        if self.dnssec_mode != 'none':
            dnssec_cfg = self.config.get('dnssec', {})
            self.dnssec_validator = DNSSECValidator(
                config=dnssec_cfg,
                trust_anchors=self.trust_anchor_manager.get_trust_anchors(),
                query_func=self._raw_query
            )
            logger.info(f"DNSSEC validation: mode={self.dnssec_mode}")
        
        # Start background tasks
        await self.root_hints.start_refresh_task()
        await self.trust_anchor_manager.start_refresh_task()
        
        logger.info("Recursive resolver initialized")
        return True
    
    async def resolve(
        self,
        qname: str,
        qtype: int,
        req_logger=None
    ) -> Optional[dns.message.Message]:
        """
        Resolve a DNS query iteratively from root servers.
        
        Args:
            qname: Query name (e.g., "www.example.com")
            qtype: Query type (e.g., dns.rdatatype.A)
            req_logger: Request-specific logger
            
        Returns:
            DNS response message or None on failure
        """
        log = req_logger or logger
        
        if not self.enabled:
            log.error("Recursive resolver not enabled")
            return None
        
        qname_obj = dns.name.from_text(qname) if isinstance(qname, str) else qname
        qname_str = str(qname_obj).lower()
        
        log.debug(f"Recursive resolve: {qname_str} {dns.rdatatype.to_text(qtype)}")
        
        try:
            response, chain_length = await self._resolve_iterative(
                qname_obj, qtype, log
            )
            
            if response:
                self.stats.record_query(True, chain_length)
                
                # DNSSEC validation
                if self.dnssec_validator:
                    status, response = await self.dnssec_validator.validate_response(
                        response, qname_str, qtype, log
                    )
                    if response is None:
                        # Validation blocked
                        self.stats.record_query(False, chain_length)
                        return self._make_servfail(qname_obj, qtype)
                
                return response
            else:
                self.stats.record_query(False, chain_length)
                return self._make_servfail(qname_obj, qtype)
                
        except Exception as e:
            log.error(f"Recursive resolution failed for {qname_str}: {e}")
            self.stats.record_query(False)
            return self._make_servfail(qname_obj, qtype)
    
    async def _resolve_iterative(
        self,
        qname: dns.name.Name,
        qtype: int,
        log
    ) -> Tuple[Optional[dns.message.Message], int]:
        """
        Core iterative resolution logic.
        
        Returns:
            (response, chain_length)
        """
        current_zone = dns.name.root
        nameservers = self._get_root_nameservers()
        chain_length = 0
        visited_zones: Set[str] = set()
        cname_chain: List[dns.name.Name] = []
        
        original_qname = qname
        
        while chain_length < self.MAX_REFERRALS:
            chain_length += 1
            zone_str = str(current_zone)
            
            if zone_str in visited_zones:
                log.warning(f"Loop detected at zone {zone_str}")
                break
            visited_zones.add(zone_str)
            
            # Check NS cache
            cached_ns = self.ns_cache.get(zone_str)
            if cached_ns:
                nameservers = cached_ns
                log.debug(f"NS cache hit for {zone_str}")
            
            if not nameservers:
                log.warning(f"No nameservers for zone {zone_str}")
                break
            
            # Query nameservers
            response = await self._query_nameservers(
                nameservers, qname, qtype, log
            )
            
            if not response:
                log.warning(f"No response from nameservers for {qname}")
                break
            
            rcode = response.rcode()
            
            # Check for answer
            if response.answer:
                # Check for CNAME
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME and rrset.name == qname:
                        if qtype == dns.rdatatype.CNAME:
                            # Asked for CNAME, got it
                            return response, chain_length
                        
                        # Follow CNAME
                        target = rrset[0].target
                        if len(cname_chain) >= self.MAX_CNAME_CHAIN:
                            log.warning(f"CNAME chain too long")
                            break
                        
                        cname_chain.append(qname)
                        qname = target
                        current_zone = dns.name.root
                        nameservers = self._get_root_nameservers()
                        log.debug(f"Following CNAME to {target}")
                        continue
                
                # Got answer
                return response, chain_length
            
            # Check for NXDOMAIN or NOERROR with no data
            if rcode == dns.rcode.NXDOMAIN:
                return response, chain_length
            
            if rcode == dns.rcode.NOERROR and not response.authority:
                # Empty response
                return response, chain_length
            
            # Check for referral (NS in authority)
            referral = self._extract_referral(response, qname)
            if referral:
                new_zone, new_ns = referral
                log.debug(f"Referral to {new_zone}: {len(new_ns)} nameservers")
                
                # Cache NS records
                ttl = self._get_min_ttl(response.authority)
                self.ns_cache.put(str(new_zone), new_ns, ttl)
                
                current_zone = new_zone
                nameservers = new_ns
                self.stats.referrals_followed += 1
                continue
            
            # No answer, no referral - return what we have
            return response, chain_length
        
        log.warning(f"Max referrals reached for {original_qname}")
        return None, chain_length
    
    def _get_root_nameservers(self) -> List[Tuple[str, List[str]]]:
        """Get root nameservers as [(name, [ips]), ...]"""
        result = []
        for server in self.root_hints.root_servers:
            ips = server.get_ips(self.prefer_ipv6)
            if ips:
                result.append((server.name, ips))
        self.stats.root_queries += 1
        return result
    
    def _extract_referral(
        self,
        response: dns.message.Message,
        qname: dns.name.Name
    ) -> Optional[Tuple[dns.name.Name, List[Tuple[str, List[str]]]]]:
        """
        Extract referral information from response.
        
        Returns:
            (zone, [(ns_name, [ips]), ...]) or None
        """
        # Find NS records in authority
        ns_records: Dict[dns.name.Name, List[str]] = {}
        referral_zone = None
        
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                # Check if this NS is for a parent of qname
                if qname.is_subdomain(rrset.name):
                    referral_zone = rrset.name
                    for rdata in rrset:
                        ns_name = rdata.target
                        if ns_name not in ns_records:
                            ns_records[ns_name] = []
        
        if not referral_zone or not ns_records:
            return None
        
        # Extract glue records from additional section
        for rrset in response.additional:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                if rrset.name in ns_records:
                    for rdata in rrset:
                        ns_records[rrset.name].append(rdata.to_text())
        
        # Build result list
        result = []
        for ns_name, ips in ns_records.items():
            if ips:
                result.append((str(ns_name), ips))
            else:
                # No glue - will need to resolve NS name
                result.append((str(ns_name), []))
        
        return (referral_zone, result) if result else None
    
    async def _query_nameservers(
        self,
        nameservers: List[Tuple[str, List[str]]],
        qname: dns.name.Name,
        qtype: int,
        log
    ) -> Optional[dns.message.Message]:
        """
        Query a list of nameservers until one responds.
        
        Args:
            nameservers: [(ns_name, [ip1, ip2, ...]), ...]
            qname: Query name
            qtype: Query type
            log: Logger
            
        Returns:
            DNS response or None
        """
        # Shuffle for load distribution
        ns_list = list(nameservers)
        random.shuffle(ns_list)
        
        for ns_name, ips in ns_list:
            if not ips:
                # Need to resolve NS name
                resolved_ips = await self._resolve_ns_name(ns_name, log)
                if not resolved_ips:
                    continue
                ips = resolved_ips
            
            for ip in ips:
                try:
                    response = await self._send_query(ip, qname, qtype, log)
                    if response:
                        return response
                except Exception as e:
                    log.debug(f"Query to {ns_name}[{ip}] failed: {e}")
                    continue
        
        return None
    
    async def _resolve_ns_name(self, ns_name: str, log) -> List[str]:
        """Resolve nameserver hostname to IPs (out-of-bailiwick glue)"""
        # Avoid infinite recursion
        ns_name_obj = dns.name.from_text(ns_name)
        
        # Try A record
        try:
            response, _ = await self._resolve_iterative(
                ns_name_obj, dns.rdatatype.A, log
            )
            if response and response.answer:
                ips = []
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        for rdata in rrset:
                            ips.append(rdata.to_text())
                if ips:
                    return ips
        except Exception as e:
            log.debug(f"Failed to resolve NS {ns_name} A: {e}")
        
        # Try AAAA record
        if self.prefer_ipv6:
            try:
                response, _ = await self._resolve_iterative(
                    ns_name_obj, dns.rdatatype.AAAA, log
                )
                if response and response.answer:
                    ips = []
                    for rrset in response.answer:
                        if rrset.rdtype == dns.rdatatype.AAAA:
                            for rdata in rrset:
                                ips.append(rdata.to_text())
                    if ips:
                        return ips
            except Exception as e:
                log.debug(f"Failed to resolve NS {ns_name} AAAA: {e}")
        
        return []
    
    async def _send_query(
        self,
        ip: str,
        qname: dns.name.Name,
        qtype: int,
        log
    ) -> Optional[dns.message.Message]:
        """Send DNS query to specific IP"""
        # Build query
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.RD  # Set RD even though we're iterating
        
        wire = query.to_wire()
        
        # Try UDP first
        try:
            response_wire = await self._udp_query(ip, wire)
            if response_wire:
                response = dns.message.from_wire(response_wire)
                
                # Check for TC (truncation)
                if response.flags & dns.flags.TC:
                    log.debug(f"Response from {ip} truncated, retrying TCP")
                    response_wire = await self._tcp_query(ip, wire)
                    if response_wire:
                        response = dns.message.from_wire(response_wire)
                
                return response
        except Exception as e:
            log.debug(f"UDP query to {ip} failed: {e}")
        
        # Fallback to TCP
        try:
            response_wire = await self._tcp_query(ip, wire)
            if response_wire:
                return dns.message.from_wire(response_wire)
        except Exception as e:
            log.debug(f"TCP query to {ip} failed: {e}")
        
        return None
    
    async def _raw_query(self, wire: bytes) -> Optional[bytes]:
        """Raw query for DNSSEC validator to fetch DNSKEY/DS"""
        # Parse query to get qname
        try:
            query = dns.message.from_wire(wire)
            if not query.question:
                return None
            
            qname = query.question[0].name
            qtype = query.question[0].rdtype
            
            # Use iterative resolution
            response, _ = await self._resolve_iterative(qname, qtype, logger)
            if response:
                return response.to_wire()
        except Exception as e:
            logger.debug(f"Raw query failed: {e}")
        
        return None
    
    async def _udp_query(self, ip: str, wire: bytes) -> Optional[bytes]:
        """Send UDP query"""
        loop = asyncio.get_running_loop()
        
        # Determine address family
        try:
            if ':' in ip:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
        except Exception as e:
            logger.debug(f"Socket creation failed: {e}")
            return None
        
        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (ip, 53)),
                timeout=self.query_timeout
            )
            await asyncio.wait_for(
                loop.sock_sendall(sock, wire),
                timeout=self.query_timeout
            )
            response = await asyncio.wait_for(
                loop.sock_recv(sock, 65535),
                timeout=self.query_timeout
            )
            return response
        except asyncio.TimeoutError:
            logger.debug(f"UDP timeout to {ip}")
            return None
        except Exception as e:
            logger.debug(f"UDP error to {ip}: {e}")
            return None
        finally:
            sock.close()
    
    async def _tcp_query(self, ip: str, wire: bytes) -> Optional[bytes]:
        """Send TCP query"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 53),
                timeout=self.query_timeout
            )
            
            try:
                # Length-prefixed message
                writer.write(len(wire).to_bytes(2, 'big') + wire)
                await writer.drain()
                
                # Read response length
                len_bytes = await asyncio.wait_for(
                    reader.readexactly(2),
                    timeout=self.query_timeout
                )
                length = int.from_bytes(len_bytes, 'big')
                
                # Read response
                response = await asyncio.wait_for(
                    reader.readexactly(length),
                    timeout=self.query_timeout
                )
                
                return response
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            logger.debug(f"TCP timeout to {ip}")
            return None
        except Exception as e:
            logger.debug(f"TCP error to {ip}: {e}")
            return None
    
    def _get_min_ttl(self, rrsets: List[dns.rrset.RRset]) -> int:
        """Get minimum TTL from rrsets"""
        ttls = [rrset.ttl for rrset in rrsets if rrset]
        return min(ttls) if ttls else 86400
    
    def _make_servfail(
        self,
        qname: dns.name.Name,
        qtype: int
    ) -> dns.message.Message:
        """Create SERVFAIL response"""
        response = dns.message.Message()
        response.flags = dns.flags.QR | dns.flags.RA
        response.set_rcode(dns.rcode.SERVFAIL)
        response.question.append(dns.rrset.RRset(qname, dns.rdataclass.IN, qtype))
        return response
    
    def get_stats(self) -> dict:
        """Get resolver statistics"""
        stats = self.stats.get_stats()
        stats['ns_cache_size'] = len(self.ns_cache.cache)
        if self.dnssec_validator:
            stats['dnssec'] = self.dnssec_validator.get_stats()
        return stats
    
    def clear_cache(self):
        """Clear all caches"""
        self.ns_cache.clear()
        if self.dnssec_validator:
            self.dnssec_validator.clear_cache()

