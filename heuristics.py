#!/usr/bin/env python3
# filename: heuristics.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.7.0 (Elaborated DGA Detection)
# -----------------------------------------------------------------------------
"""
Heuristic analysis for identifying suspicious domains based on:
- Shannon Entropy (randomness)
- DGA patterns (Linguistic anomalies)
- Typosquatting (Levenshtein distance)
- Length and character composition
"""

import math
import os
import logging
import re
from typing import List, Tuple
from utils import get_logger

logger = get_logger("Heuristics")

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
        if not text: return 0.0
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
        if len(s1) < len(s2): return self._levenshtein(s2, s1)
        if len(s2) == 0: return len(s1)
        
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
        label_len = len(label)
        for target in self.targets:
            if abs(label_len - len(target)) > 1: continue
            if label == target: continue
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
        if len(label) < 5: return 0, ""
        if label.isdigit(): return 0, "" # Handled by numeric check
        
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

    def analyze(self, domain: str) -> Tuple[int, List[str]]:
        if not self.enabled or not domain: return 0, []

        score = 0
        reasons = []
        
        clean_domain = domain.rstrip('.')
        parts = clean_domain.split('.')
        debug_on = logger.isEnabledFor(logging.DEBUG)
        if debug_on: logger.debug(f"Analyzing heuristics for: {clean_domain}")
        
        # 1. High-Risk TLD
        if parts:
            tld = parts[-1].lower()
            if tld in HIGH_RISK_TLDS:
                score += 2
                reasons.append(f"High-risk TLD (.{tld})")
                if debug_on: logger.debug(f"  [+] Penalty: High-risk TLD '.{tld}' -> Score: {score}")

        # 2. Label Count
        if len(parts) > 4:
            score += 1
            reasons.append(f"High label count ({len(parts)})")
            if debug_on: logger.debug(f"  [+] Penalty: High label count ({len(parts)}) -> Score: {score}")
            
        total_len = len(clean_domain)
        # 3. Total Length
        if total_len > 80:
            score += 1
            reasons.append(f"Excessive total length ({total_len})")
            if debug_on: logger.debug(f"  [+] Penalty: Excessive length ({total_len}) -> Score: {score}")

        max_entropy = 0.0
        max_hyphens = 0
        digit_count = sum(c.isdigit() for c in clean_domain)
        
        for part in parts:
            if not part: continue
            
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
                if debug_on: logger.debug(f"  [+] Penalty: Long label '{part[:15]}...' -> Score: {score}")
                
            # 7. Typosquatting
            if len(part) > 3 and self._is_typosquat(part):
                score += 4
                reasons.append(f"Possible typosquatting: {part}")
                if debug_on: logger.debug(f"  [+] Penalty: Typosquatting '{part}' -> Score: {score}")

            # 8. Numeric Label
            if part.isdigit():
                score += 1
                reasons.append(f"Numeric label '{part}'")
                if debug_on: logger.debug(f"  [+] Penalty: Numeric label '{part}' -> Score: {score}")

            # 9. Elaborated DGA Check
            dga_score, dga_reason = self._check_dga(part)
            if dga_score > 0:
                score += dga_score
                reasons.append(f"DGA: {part} ({dga_reason})")
                if debug_on: logger.debug(f"  [+] Penalty: DGA '{part}' ({dga_reason}) -> Score: {score}")

        # Evaluate Aggregates
        if max_entropy > self.entropy_high:
            score += 3
            reasons.append(f"High entropy ({max_entropy:.2f})")
            if debug_on: logger.debug(f"  [+] Penalty: High entropy ({max_entropy:.2f}) -> Score: {score}")
        elif max_entropy > self.entropy_suspicious:
            score += 1
            reasons.append(f"Suspicious entropy ({max_entropy:.2f})")
            if debug_on: logger.debug(f"  [+] Penalty: Suspicious entropy ({max_entropy:.2f}) -> Score: {score}")
            
        if max_hyphens > 1:
            score += 1
            reasons.append(f"Excessive hyphens ({max_hyphens})")
            if debug_on: logger.debug(f"  [+] Penalty: Excessive hyphens ({max_hyphens}) -> Score: {score}")
            
        if total_len > 0 and (digit_count / total_len) > 0.30:
            score += 1
            reasons.append(f"High numeric volume ({digit_count}/{total_len})")
            if debug_on: logger.debug(f"  [+] Penalty: High numeric volume ({digit_count}/{total_len}) -> Score: {score}")

        final_score = min(5, score)
        if debug_on and final_score > 0:
            logger.debug(f"  = Final Score: {final_score}/5 | Reasons: {reasons}")

        return final_score, reasons

