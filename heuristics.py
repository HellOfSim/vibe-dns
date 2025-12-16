#!/usr/bin/env python3
# filename: heuristics.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.0.0 (RR-Type Aware Heuristics)
# -----------------------------------------------------------------------------
"""
Heuristic analysis for identifying suspicious domains based on:
- Shannon Entropy (randomness)
- DGA patterns (Linguistic anomalies)
- Typosquatting (Levenshtein distance)
- Length and character composition

Now includes RR-type awareness to prevent false positives for:
- PTR records (reverse DNS)
- SRV records (service discovery)
- DNSSEC records
- Other special record types
"""

import math
import os
import logging
import re
from typing import List, Tuple, Optional
from utils import get_logger

logger = get_logger("Heuristics")

# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_TARGETS = [
    "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "instagram", "whatsapp", "twitter", "linkedin",
    "paypal", "dropbox", "github", "gitlab", "salesforce"
]

HIGH_RISK_TLDS = {
    'xyz', 'top', 'club', 'work', 'loan', 'win', 'click', 'country',
    'kim', 'men', 'mom', 'party', 'review', 'science', 'stream',
    'trade', 'gdn', 'racing', 'jetzt', 'download', 'accountant',
    'bid', 'date', 'faith', 'pro', 'site', 'space', 'website', 'online',
    'zip', 'mov',
    'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'sur', 'ci', 'sz'
}

# Domains that are structurally exempt from heuristics
# These have legitimately "random-looking" names by design
EXEMPT_SUFFIXES = {
    # Reverse DNS
    'in-addr.arpa',
    'ip6.arpa',
    # mDNS/Bonjour/Local
    'local',
    'localhost',
    # Private use (RFC 8375)
    'home.arpa',
    'internal',
    'private',
    'corp',
    'lan',
    'home',
    # Special use
    'onion',
    'test',
    'example',
    'invalid',
}

# Domain patterns that indicate service/infrastructure records
EXEMPT_PATTERNS = {
    # Service discovery
    '_tcp.',
    '_udp.',
    '_tls.',
    '_sctp.',
    # Email authentication
    '_domainkey.',
    '_dkim.',
    '_dmarc.',
    '_spf.',
    # DNSSEC
    '_dsset.',
    # SIP/VoIP
    '_sip.',
    '_sips.',
    # XMPP
    '_xmpp-client.',
    '_xmpp-server.',
    # Generic service prefix
    '_http.',
    '_https.',
}

# Query types that should skip or reduce heuristics
# These types often have legitimately unusual domain patterns
RELAXED_QTYPES = {
    'PTR',       # Reverse lookups - IP addresses look random
    'SRV',       # Service records - _service._proto.name format
    'NAPTR',     # Naming authority - regex patterns in names
    'DNSKEY',    # DNSSEC keys
    'DS',        # Delegation signer
    'NSEC',      # DNSSEC denial
    'NSEC3',     # DNSSEC denial (hashed)
    'NSEC3PARAM',# NSEC3 parameters
    'RRSIG',     # DNSSEC signatures
    'CDNSKEY',   # Child DNSKEY
    'CDS',       # Child DS
    'TLSA',      # TLS authentication
    'SSHFP',     # SSH fingerprints
    'CAA',       # Cert authority authorization
    'SMIMEA',    # S/MIME cert association
    'OPENPGPKEY',# OpenPGP key
    'SVCB',      # Service binding
    'HTTPS',     # HTTPS service binding
    'TXT',       # Text records (often have underscores)
    'ANY',       # Meta-query
    'AXFR',      # Zone transfer
    'IXFR',      # Incremental zone transfer
}


class DomainHeuristics:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        self.block_threshold = self.config.get('block_threshold', 4)

        # Entropy Config
        self.entropy_high = self.config.get('entropy_threshold_high', 3.8)
        self.entropy_suspicious = self.config.get('entropy_threshold_suspicious', 3.2)

        # Initialize Targets
        self.targets = set(DEFAULT_TARGETS)
        target_file = self.config.get('typosquat_file')
        if target_file:
            self._load_targets(target_file)

        if self.enabled:
            logger.info(f"Heuristics enabled: threshold={self.block_threshold}, "
                       f"entropy_high={self.entropy_high}, entropy_suspicious={self.entropy_suspicious}")

    def _load_targets(self, filepath: str):
        if not os.path.exists(filepath):
            if self.enabled:
                logger.warning(f"Typosquat file '{filepath}' not found. Using internal defaults.")
            return
        try:
            count = 0
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        self.targets.add(line)
                        count += 1
            logger.info(f"Loaded {count} typosquat targets from {filepath}")
        except Exception as e:
            logger.error(f"Error loading typosquat targets: {e}")

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        length = len(text)
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1

        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _is_typosquat(self, label: str) -> bool:
        """Check if label is a typosquat of known targets."""
        label_len = len(label)
        for target in self.targets:
            if abs(label_len - len(target)) > 1:
                continue
            if label == target:
                continue
            if self._levenshtein(label, target) == 1:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"    - Typosquat match: '{label}' ~= '{target}'")
                return True
        return False

    def _check_dga(self, label: str) -> Tuple[int, str]:
        """
        Linguistic analysis to detect DGA (Domain Generation Algorithms).
        Returns: (Score Penalty, Reason)
        """
        if len(label) < 5:
            return 0, ""
        if label.isdigit():
            return 0, ""  # Handled by numeric check

        score = 0
        reasons = []

        # 1. Consonant Streak Analysis
        # 'y' is treated as a vowel here to avoid flagging words like 'rhythms'
        consonants = "bcdfghjklmnpqrstvwxz"
        max_streak = 0
        current_streak = 0

        for char in label:
            if char in consonants:
                current_streak += 1
                max_streak = max(max_streak, current_streak)
            else:
                current_streak = 0

        # English rarely has > 4 consecutive consonants
        if max_streak >= 5:
            score += 2
            reasons.append(f"Consonant streak ({max_streak})")

        # 2. Vowel Ratio Analysis
        # Count 'y' as vowel here for fairness
        vowels = "aeiouy"
        vowel_count = sum(1 for c in label if c in vowels)
        ratio = vowel_count / len(label)

        # Typical English is ~30-40%. DGA is often < 10%
        if ratio < 0.15:
            score += 1
            reasons.append(f"Low vowel ratio ({ratio:.0%})")

        # 3. Repeated Character Analysis
        # Detects "mashing" like 'aaabbb'
        if re.search(r'(.)\1\1\1', label):
            score += 1
            reasons.append("Repeated chars")

        return score, ", ".join(reasons)

    def is_exempt(self, domain: str, qtype_str: Optional[str] = None) -> Tuple[bool, str]:
        """
        Check if domain/qtype combination is exempt from heuristics.
        
        Returns:
            Tuple of (is_exempt, reason)
        """
        # Check query type exemption
        if qtype_str and qtype_str.upper() in RELAXED_QTYPES:
            return True, f"qtype={qtype_str}"

        clean = domain.rstrip('.').lower()

        # Check suffix exemption
        parts = clean.split('.')
        if parts:
            tld = parts[-1]
            if tld in EXEMPT_SUFFIXES:
                return True, f"exempt TLD .{tld}"

        # Check for two-part suffix (e.g., home.arpa)
        if len(parts) >= 2:
            suffix = f"{parts[-2]}.{parts[-1]}"
            if suffix in EXEMPT_SUFFIXES:
                return True, f"exempt suffix .{suffix}"

        # Check pattern exemption (service discovery, etc.)
        for pattern in EXEMPT_PATTERNS:
            if pattern in clean:
                return True, f"exempt pattern {pattern}"

        # Check for underscore-prefixed labels (service records)
        for part in parts:
            if part.startswith('_'):
                return True, f"service label _{part[1:]}"

        return False, ""

    def analyze(self, domain: str, qtype_str: Optional[str] = None) -> Tuple[int, List[str]]:
        """
        Analyze domain for suspicious patterns.
        
        Args:
            domain: The domain name to analyze
            qtype_str: Optional query type (e.g., 'PTR', 'SRV') for context-aware analysis
        
        Returns:
            Tuple of (score, list of reasons)
        """
        if not self.enabled or not domain:
            return 0, []

        clean_domain = domain.rstrip('.').lower()
        debug_on = logger.isEnabledFor(logging.DEBUG)

        # Check for exemptions first
        is_exempt, exempt_reason = self.is_exempt(clean_domain, qtype_str)
        if is_exempt:
            if debug_on:
                logger.debug(f"Heuristics skipped for {clean_domain} ({exempt_reason})")
            return 0, []

        score = 0
        reasons = []
        parts = clean_domain.split('.')

        if debug_on:
            logger.debug(f"Analyzing heuristics for: {clean_domain}")

        # 1. High-Risk TLD
        if parts:
            tld = parts[-1].lower()
            if tld in HIGH_RISK_TLDS:
                score += 2
                reasons.append(f"High-risk TLD (.{tld})")
                if debug_on:
                    logger.debug(f"  [+] Penalty: High-risk TLD '.{tld}' -> Score: {score}")

        # 2. Label Count
        if len(parts) > 4:
            score += 1
            reasons.append(f"High label count ({len(parts)})")
            if debug_on:
                logger.debug(f"  [+] Penalty: High label count ({len(parts)}) -> Score: {score}")

        total_len = len(clean_domain)

        # 3. Total Length
        if total_len > 80:
            score += 1
            reasons.append(f"Excessive total length ({total_len})")
            if debug_on:
                logger.debug(f"  [+] Penalty: Excessive length ({total_len}) -> Score: {score}")

        max_entropy = 0.0
        max_hyphens = 0
        digit_count = sum(c.isdigit() for c in clean_domain)

        for part in parts:
            if not part:
                continue

            # Skip underscore-prefixed labels (service records like _dmarc)
            if part.startswith('_'):
                continue

            # 4. Entropy
            entropy = self._shannon_entropy(part)
            max_entropy = max(max_entropy, entropy)

            # 5. Hyphens
            hyphens = part.count('-')
            max_hyphens = max(max_hyphens, hyphens)

            # 6. Length
            if len(part) > 30:
                score += 1
                reasons.append(f"Very long label: {part[:10]}...")
                if debug_on:
                    logger.debug(f"  [+] Penalty: Long label '{part[:15]}...' -> Score: {score}")

            # 7. Typosquatting
            if len(part) > 3 and self._is_typosquat(part):
                score += 4
                reasons.append(f"Possible typosquatting: {part}")
                if debug_on:
                    logger.debug(f"  [+] Penalty: Typosquatting '{part}' -> Score: {score}")

            # 8. Numeric Label
            if part.isdigit():
                score += 1
                reasons.append(f"Numeric label '{part}'")
                if debug_on:
                    logger.debug(f"  [+] Penalty: Numeric label '{part}' -> Score: {score}")

            # 9. Elaborated DGA Check
            dga_score, dga_reason = self._check_dga(part)
            if dga_score > 0:
                score += dga_score
                reasons.append(f"DGA: {part} ({dga_reason})")
                if debug_on:
                    logger.debug(f"  [+] Penalty: DGA '{part}' ({dga_reason}) -> Score: {score}")

        # Evaluate Aggregates
        if max_entropy > self.entropy_high:
            score += 3
            reasons.append(f"High entropy ({max_entropy:.2f})")
            if debug_on:
                logger.debug(f"  [+] Penalty: High entropy ({max_entropy:.2f}) -> Score: {score}")
        elif max_entropy > self.entropy_suspicious:
            score += 1
            reasons.append(f"Suspicious entropy ({max_entropy:.2f})")
            if debug_on:
                logger.debug(f"  [+] Penalty: Suspicious entropy ({max_entropy:.2f}) -> Score: {score}")

        if max_hyphens > 1:
            score += 1
            reasons.append(f"Excessive hyphens ({max_hyphens})")
            if debug_on:
                logger.debug(f"  [+] Penalty: Excessive hyphens ({max_hyphens}) -> Score: {score}")

        if total_len > 0 and (digit_count / total_len) > 0.30:
            score += 1
            reasons.append(f"High numeric volume ({digit_count}/{total_len})")
            if debug_on:
                logger.debug(f"  [+] Penalty: High numeric volume ({digit_count}/{total_len}) -> Score: {score}")

        final_score = min(5, score)
        if debug_on and final_score > 0:
            logger.debug(f"  = Final Score: {final_score}/5 | Reasons: {reasons}")

        return final_score, reasons

