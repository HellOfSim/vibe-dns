#!/usr/bin/env python3
# filename: root_hints.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# -----------------------------------------------------------------------------
"""
Root Hints and Trust Anchor management for recursive resolution.
Supports loading from:
- Built-in defaults
- URL (IANA/InterNIC)
- Local file
"""

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from utils import get_logger

logger = get_logger("RootHints")


# =============================================================================
# BUILT-IN ROOT SERVERS (as of 2024)
# =============================================================================
BUILTIN_ROOT_SERVERS = [
    # (name, ipv4, ipv6)
    ("a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30"),
    ("b.root-servers.net", "170.247.170.2", "2801:1b8:10::b"),
    ("c.root-servers.net", "192.33.4.12", "2001:500:2::c"),
    ("d.root-servers.net", "199.7.91.13", "2001:500:2d::d"),
    ("e.root-servers.net", "192.203.230.10", "2001:500:a8::e"),
    ("f.root-servers.net", "192.5.5.241", "2001:500:2f::f"),
    ("g.root-servers.net", "192.112.36.4", "2001:500:12::d0d"),
    ("h.root-servers.net", "198.97.190.53", "2001:500:1::53"),
    ("i.root-servers.net", "192.36.148.17", "2001:7fe::53"),
    ("j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30"),
    ("k.root-servers.net", "193.0.14.129", "2001:7fd::1"),
    ("l.root-servers.net", "199.7.83.42", "2001:500:9f::42"),
    ("m.root-servers.net", "202.12.27.33", "2001:dc3::35"),
]


# =============================================================================
# BUILT-IN ROOT TRUST ANCHORS (as of 2024)
# =============================================================================
# Key tag 20326 is the current root KSK (since 2017 key rollover)
# Key tag 38696 was the previous root KSK (retired)
BUILTIN_TRUST_ANCHORS = {
    20326: {
        'algorithm': 8,  # RSASHA256
        'digest_type': 2,  # SHA-256
        'digest': 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
        'flags': 257,  # KSK
        'protocol': 3,
        'comment': 'Root KSK 2017'
    },
}


@dataclass
class RootServer:
    """Root server information"""
    name: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    
    def get_ips(self, prefer_ipv6: bool = False) -> List[str]:
        """Get available IPs, optionally preferring IPv6"""
        ips = []
        if prefer_ipv6:
            if self.ipv6:
                ips.append(self.ipv6)
            if self.ipv4:
                ips.append(self.ipv4)
        else:
            if self.ipv4:
                ips.append(self.ipv4)
            if self.ipv6:
                ips.append(self.ipv6)
        return ips


class RootHintsManager:
    """Manages root server hints for recursive resolution"""
    
    def __init__(self, config: dict = None):
        """
        Initialize root hints manager.
        
        Args:
            config: Root hints configuration
                source: "builtin" | "url" | "file"
                url: URL to fetch named.root
                file: Path to named.root file
                refresh_interval: Seconds between refreshes
        """
        config = config or {}
        self.source = config.get('source', 'builtin')
        self.url = config.get('url', 'https://www.internic.net/domain/named.root')
        self.file_path = config.get('file')
        self.refresh_interval = config.get('refresh_interval', 86400)
        
        self.root_servers: List[RootServer] = []
        self.last_refresh = 0
        self._refresh_task = None
    
    async def initialize(self) -> bool:
        """Load root hints from configured source"""
        try:
            if self.source == "builtin":
                self._load_builtin()
            elif self.source == "url":
                await self._load_from_url()
            elif self.source == "file":
                self._load_from_file()
            else:
                logger.warning(f"Unknown root hints source: {self.source}, using builtin")
                self._load_builtin()
            
            logger.info(f"Root hints loaded: {len(self.root_servers)} servers from {self.source}")
            return len(self.root_servers) > 0
            
        except Exception as e:
            logger.error(f"Failed to load root hints: {e}")
            logger.info("Falling back to builtin root hints")
            self._load_builtin()
            return len(self.root_servers) > 0
    
    def _load_builtin(self):
        """Load built-in root server list"""
        self.root_servers = [
            RootServer(name=name, ipv4=ipv4, ipv6=ipv6)
            for name, ipv4, ipv6 in BUILTIN_ROOT_SERVERS
        ]
        self.last_refresh = asyncio.get_event_loop().time()
    
    async def _load_from_url(self):
        """Fetch and parse named.root from URL"""
        try:
            import httpx
            
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(self.url)
                response.raise_for_status()
                content = response.text
            
            self._parse_named_root(content)
            self.last_refresh = asyncio.get_event_loop().time()
            logger.info(f"Root hints fetched from {self.url}")
            
        except ImportError:
            logger.warning("httpx not available, falling back to builtin")
            self._load_builtin()
        except Exception as e:
            logger.error(f"Failed to fetch root hints from URL: {e}")
            raise
    
    def _load_from_file(self):
        """Load and parse named.root from file"""
        if not self.file_path:
            raise ValueError("No file path configured for root hints")
        
        path = Path(self.file_path)
        if not path.exists():
            raise FileNotFoundError(f"Root hints file not found: {self.file_path}")
        
        content = path.read_text()
        self._parse_named_root(content)
        self.last_refresh = asyncio.get_event_loop().time()
        logger.info(f"Root hints loaded from {self.file_path}")
    
    def _parse_named_root(self, content: str):
        """Parse named.root format file"""
        servers: Dict[str, RootServer] = {}
        
        # Pattern for NS, A, and AAAA records
        # .                        3600000      NS    A.ROOT-SERVERS.NET.
        # A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
        # A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            parts = line.split()
            if len(parts) < 4:
                continue
            
            name = parts[0].lower().rstrip('.')
            rtype = parts[-2].upper()
            rdata = parts[-1]
            
            if rtype == 'NS' and parts[0] == '.':
                # Root NS record
                ns_name = rdata.lower().rstrip('.')
                if ns_name not in servers:
                    servers[ns_name] = RootServer(name=ns_name)
            
            elif rtype == 'A':
                # IPv4 address
                if name in servers:
                    servers[name].ipv4 = rdata
                elif name.endswith('.root-servers.net'):
                    servers[name] = RootServer(name=name, ipv4=rdata)
            
            elif rtype == 'AAAA':
                # IPv6 address
                if name in servers:
                    servers[name].ipv6 = rdata
                elif name.endswith('.root-servers.net'):
                    servers[name] = RootServer(name=name, ipv6=rdata)
        
        self.root_servers = list(servers.values())
    
    def get_root_servers(self, prefer_ipv6: bool = False) -> List[Tuple[str, str]]:
        """
        Get list of (name, ip) tuples for root servers.
        
        Args:
            prefer_ipv6: Prefer IPv6 addresses if available
            
        Returns:
            List of (server_name, ip_address) tuples
        """
        result = []
        for server in self.root_servers:
            for ip in server.get_ips(prefer_ipv6):
                result.append((server.name, ip))
        return result
    
    def get_random_root(self, prefer_ipv6: bool = False) -> Optional[Tuple[str, str]]:
        """Get a random root server"""
        import random
        servers = self.get_root_servers(prefer_ipv6)
        return random.choice(servers) if servers else None
    
    async def start_refresh_task(self):
        """Start background refresh task"""
        if self.source == "builtin":
            return  # No refresh needed for builtin
        
        self._refresh_task = asyncio.create_task(self._refresh_loop())
    
    async def _refresh_loop(self):
        """Background loop to refresh root hints"""
        while True:
            await asyncio.sleep(self.refresh_interval)
            try:
                if self.source == "url":
                    await self._load_from_url()
                elif self.source == "file":
                    self._load_from_file()
            except Exception as e:
                logger.warning(f"Failed to refresh root hints: {e}")


class TrustAnchorManager:
    """Manages DNSSEC trust anchors for the root zone"""
    
    def __init__(self, config: dict = None):
        """
        Initialize trust anchor manager.
        
        Args:
            config: Trust anchor configuration
                source: "builtin" | "url" | "file"
                url: URL to fetch root-anchors.xml
                file: Path to root-anchors.xml file
                refresh_interval: Seconds between refreshes
        """
        config = config or {}
        self.source = config.get('source', 'builtin')
        self.url = config.get('url', 'https://data.iana.org/root-anchors/root-anchors.xml')
        self.file_path = config.get('file')
        self.refresh_interval = config.get('refresh_interval', 86400)
        
        self.trust_anchors: Dict[int, dict] = {}
        self.last_refresh = 0
        self._refresh_task = None
    
    async def initialize(self) -> bool:
        """Load trust anchors from configured source"""
        try:
            if self.source == "builtin":
                self._load_builtin()
            elif self.source == "url":
                await self._load_from_url()
            elif self.source == "file":
                self._load_from_file()
            else:
                logger.warning(f"Unknown trust anchor source: {self.source}, using builtin")
                self._load_builtin()
            
            logger.info(f"Trust anchors loaded: {len(self.trust_anchors)} anchors from {self.source}")
            for key_tag, anchor in self.trust_anchors.items():
                logger.debug(f"  Key tag {key_tag}: alg={anchor['algorithm']}, "
                           f"digest_type={anchor['digest_type']}")
            
            return len(self.trust_anchors) > 0
            
        except Exception as e:
            logger.error(f"Failed to load trust anchors: {e}")
            logger.info("Falling back to builtin trust anchors")
            self._load_builtin()
            return len(self.trust_anchors) > 0
    
    def _load_builtin(self):
        """Load built-in trust anchors"""
        self.trust_anchors = BUILTIN_TRUST_ANCHORS.copy()
        self.last_refresh = asyncio.get_event_loop().time()
    
    async def _load_from_url(self):
        """Fetch and parse root-anchors.xml from URL"""
        try:
            import httpx
            
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(self.url)
                response.raise_for_status()
                content = response.text
            
            self._parse_root_anchors_xml(content)
            self.last_refresh = asyncio.get_event_loop().time()
            logger.info(f"Trust anchors fetched from {self.url}")
            
        except ImportError:
            logger.warning("httpx not available, falling back to builtin")
            self._load_builtin()
        except Exception as e:
            logger.error(f"Failed to fetch trust anchors from URL: {e}")
            raise
    
    def _load_from_file(self):
        """Load and parse root-anchors.xml from file"""
        if not self.file_path:
            raise ValueError("No file path configured for trust anchors")
        
        path = Path(self.file_path)
        if not path.exists():
            raise FileNotFoundError(f"Trust anchors file not found: {self.file_path}")
        
        content = path.read_text()
        self._parse_root_anchors_xml(content)
        self.last_refresh = asyncio.get_event_loop().time()
        logger.info(f"Trust anchors loaded from {self.file_path}")
    
    def _parse_root_anchors_xml(self, content: str):
        """
        Parse IANA root-anchors.xml format.
        
        Example structure:
        <TrustAnchor>
            <Zone>.</Zone>
            <KeyDigest validFrom="2017-02-02T00:00:00+00:00">
                <KeyTag>20326</KeyTag>
                <Algorithm>8</Algorithm>
                <DigestType>2</DigestType>
                <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
            </KeyDigest>
        </TrustAnchor>
        """
        try:
            root = ET.fromstring(content)
            anchors = {}
            
            # Find all KeyDigest elements
            for key_digest in root.iter('KeyDigest'):
                try:
                    key_tag_elem = key_digest.find('KeyTag')
                    algorithm_elem = key_digest.find('Algorithm')
                    digest_type_elem = key_digest.find('DigestType')
                    digest_elem = key_digest.find('Digest')
                    
                    if None in (key_tag_elem, algorithm_elem, digest_type_elem, digest_elem):
                        continue
                    
                    key_tag = int(key_tag_elem.text)
                    algorithm = int(algorithm_elem.text)
                    digest_type = int(digest_type_elem.text)
                    digest = digest_elem.text.strip().upper()
                    
                    # Check validity dates if present
                    valid_from = key_digest.get('validFrom')
                    valid_until = key_digest.get('validUntil')
                    
                    # TODO: Check if anchor is currently valid based on dates
                    
                    anchors[key_tag] = {
                        'algorithm': algorithm,
                        'digest_type': digest_type,
                        'digest': digest,
                        'valid_from': valid_from,
                        'valid_until': valid_until,
                    }
                    
                except (ValueError, AttributeError) as e:
                    logger.warning(f"Failed to parse KeyDigest: {e}")
                    continue
            
            if anchors:
                self.trust_anchors = anchors
            else:
                logger.warning("No valid trust anchors found in XML, keeping existing")
                
        except ET.ParseError as e:
            logger.error(f"Failed to parse trust anchors XML: {e}")
            raise
    
    def get_trust_anchors(self) -> Dict[int, dict]:
        """Get all trust anchors"""
        return self.trust_anchors.copy()
    
    def get_anchor(self, key_tag: int) -> Optional[dict]:
        """Get specific trust anchor by key tag"""
        return self.trust_anchors.get(key_tag)
    
    async def start_refresh_task(self):
        """Start background refresh task"""
        if self.source == "builtin":
            return  # No refresh needed for builtin
        
        self._refresh_task = asyncio.create_task(self._refresh_loop())
    
    async def _refresh_loop(self):
        """Background loop to refresh trust anchors"""
        while True:
            await asyncio.sleep(self.refresh_interval)
            try:
                if self.source == "url":
                    await self._load_from_url()
                elif self.source == "file":
                    self._load_from_file()
            except Exception as e:
                logger.warning(f"Failed to refresh trust anchors: {e}")

