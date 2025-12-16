#!/usr/bin/env python3
# filename: geoip_compiler.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 8.2.0 (Memory-Efficient Mode + Optimizations)
# -----------------------------------------------------------------------------
"""
Unified compiler for GeoIP databases with ASN support and validation.
Compiles MMDB OR JSON + GeoNames into a memory-mappable binary format.
"""

import urllib.request
import os
import time
import struct
import logging
import sys
import socket
import orjson as json
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

from geo_regions import (
    CONTINENTS, REGION_DEFINITIONS, COUNTRY_TO_CONTINENT,
    get_continent_name, get_country_continent, get_country_regions
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("GeoIPCompiler")

GEONAMES_BASE_URL = "https://download.geonames.org/export/dump/"

# --- FAST CIDR PARSING HELPER ---
def parse_cidr_fast(cidr: str) -> Tuple[int, int, int]:
    try:
        if '/' not in cidr:
            ip_str = cidr
            prefix = -1
        else:
            ip_str, prefix_str = cidr.split('/')
            prefix = int(prefix_str)

        if ':' in ip_str:
            # IPv6
            prefix = 128 if prefix == -1 else prefix
            packed = socket.inet_pton(socket.AF_INET6, ip_str)
            hi, lo = struct.unpack("!QQ", packed)
            ip_int = (hi << 64) | lo
            
            if prefix == 128:
                return 6, ip_int, ip_int
            
            mask = (1 << 128) - (1 << (128 - prefix))
            start = ip_int & mask
            end = start | ((1 << (128 - prefix)) - 1)
            return 6, start, end
        else:
            # IPv4
            prefix = 32 if prefix == -1 else prefix
            packed = socket.inet_aton(ip_str)
            ip_int = struct.unpack("!I", packed)[0]
            
            if prefix == 32:
                return 4, ip_int, ip_int
            
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            start = ip_int & mask
            end = start | (mask ^ 0xFFFFFFFF)
            return 4, start, end
    except Exception:
        return 0, 0, 0

# ============================================================================
# PHASE 1: GeoNames (Standard)
# ============================================================================

class GeoNamesCompiler:
    def __init__(self, cache_dir="./geonames_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.countries = {}
        self.continent_map = {}
        self.region_map = {}
        self.country_name_map = {}
    
    def download_file(self, filename: str) -> Path:
        local_path = self.cache_dir / filename
        if local_path.exists(): 
            return local_path
        url = GEONAMES_BASE_URL + filename
        logger.info(f"  ⬇ Downloading {filename}...")
        try:
            urllib.request.urlretrieve(url, local_path)
            return local_path
        except Exception:
            logger.warning(f"    Download failed: {filename}. Using empty fallback.")
            with open(local_path, 'w') as f: 
                f.write("")
            return local_path
    
    def parse_country_info(self) -> Dict:
        logger.info("  📋 Parsing country information...")
        path = self.download_file("countryInfo.txt")
        countries = {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip() or line.startswith('#'): 
                        continue
                    parts = line.split('\t')
                    if len(parts) < 19: 
                        continue
                    iso2, name, continent = parts[0], parts[4], parts[8]
                    countries[iso2] = {'iso2': iso2, 'name': name, 'continent': continent}
                    self.country_name_map[name.upper()] = iso2
        except Exception: 
            pass
        return countries
    
    def build_continent_mappings(self) -> Dict:
        continent_countries = defaultdict(list)
        for iso2, data in self.countries.items():
            continent_countries[data['continent']].append(iso2)
        
        self.continent_map = {}
        for code, info in CONTINENTS.items():
            countries = continent_countries.get(code, [])
            self.continent_map[code] = {'name': info['name'], 'countries': countries}
            self.continent_map[info['name']] = {'name': info['name'], 'countries': countries}
            
        return self.continent_map
    
    def build_custom_regions(self) -> Dict:
        self.region_map = REGION_DEFINITIONS
        return self.region_map
    
    def compile_geonames(self) -> str:
        self.countries = self.parse_country_info()
        self.build_continent_mappings()
        self.build_custom_regions()
        return "internal_memory"

    def export_rules_text(self, filename: str):
        logger.info(f"📝 Exporting GeoIP rules reference to {filename}")
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 90 + "\n")
            f.write(" VIBE-DNS GEOIP RULE REFERENCE\n")
            f.write("=" * 90 + "\n\n")
            f.write("Use these tags in your blocklists or policy files.\n")
            f.write("Syntax:\n")
            f.write("  @@TAG  - Blocks on BOTH query (ccTLD) and answer (IP)\n")
            f.write("  @TAG   - Blocks ONLY on query (ccTLD)\n")
            f.write("  @AS###  - Blocks on ASN (answer IP only)\n\n")
            
            # Continents
            f.write("-" * 90 + "\n")
            f.write(" CONTINENTS\n")
            f.write("-" * 90 + "\n")
            f.write(f"{'Code':<7}| {'Rule (Both)':<15}| {'Rule (Query)':<15}| {'Name':<30}\n")
            f.write("-" * 90 + "\n")
            
            for code, info in sorted(CONTINENTS.items()):
                f.write(f"{code:<7}| @@{code:<13}| @{code:<14}| {info['name']:<30}\n")
                f.write(f"{'':7}| @@{info['name']:<13}| @{info['name']:<14}| {info['name']} (Alias)\n")
            
            # Regions
            f.write("\n" + "-" * 90 + "\n")
            f.write(" REGIONS\n")
            f.write("-" * 90 + "\n")
            
            for region_name in sorted(REGION_DEFINITIONS.keys()):
                region_data = REGION_DEFINITIONS[region_name]
                countries = region_data.get('countries', [])
                desc = region_data.get('description', '')
                
                f.write(f"Region:       {region_name}\n")
                f.write(f"Rule (Both):  @@{region_name}\n")
                f.write(f"Rule (Query): @{region_name}\n")
                if desc:
                    f.write(f"Description:  {desc}\n")
                f.write(f"Countries:    {', '.join(sorted(countries))}\n")
                f.write("-" * 40 + "\n")
            
            # Countries
            f.write("\n" + "-" * 90 + "\n")
            f.write(" COUNTRIES (ISO 3166-1 alpha-2)\n")
            f.write("-" * 90 + "\n")
            f.write(f"{'ISO':<7}| {'Rule (Both)':<15}| {'Rule (Query)':<15}| {'Continent':<11}| {'Name':<30}\n")
            f.write("-" * 90 + "\n")
            
            for iso2, data in sorted(self.countries.items()):
                cont = data.get('continent', 'XX')
                name = data.get('name', 'Unknown')
                f.write(f"{iso2:<7}| @@{iso2:<13}| @{iso2:<14}| {cont:<11}| {name:<30}\n")
            
            # ASN note
            f.write("\n" + "-" * 90 + "\n")
            f.write(" ASN (Autonomous System Numbers)\n")
            f.write("-" * 90 + "\n")
            f.write("Syntax: @AS<number> (e.g., @AS13335 for Cloudflare)\n")
            f.write("ASN rules block based on IP address ownership/routing.\n")
            f.write("Use --export-asn to generate a full ASN list from your database.\n")
        
        logger.info(f"✓ Rules reference exported to {filename}")

# ============================================================================
# PHASE 2: Unified Compiler
# ============================================================================

class UnifiedGeoIPCompiler:
    def __init__(self, source_path: str, source_type: str, geo_compiler: GeoNamesCompiler, 
                 ip_versions: str = 'both', memory_efficient: bool = False):
        self.source_path = Path(source_path)
        self.source_type = source_type
        self.ip_versions = ip_versions.lower()
        self.memory_efficient = memory_efficient
        
        # Memory-efficient mode: stream to temp file instead of dict
        if memory_efficient:
            self._temp_file = tempfile.NamedTemporaryFile(mode='w+b', delete=False, suffix='.tmp')
            self._temp_path = self._temp_file.name
            self.ip_ranges = None
            self._region_cache = None
        else:
            self.ip_ranges = {}
            self._region_cache = {}
            self._temp_file = None
        
        self.region_map = geo_compiler.region_map
        self.continent_map = geo_compiler.continent_map
        self.country_infos = geo_compiler.countries
        self.country_names = {c: d['name'] for c, d in geo_compiler.countries.items()}
        
        self.continent_names = {
            code: info['name'] 
            for code, info in CONTINENTS.items()
        }

    def extract(self):
        if self.source_type == 'json':
            self._extract_json()
        elif self.source_type == 'mmdb':
            self._extract_mmdb()

    def _extract_json(self):
        logger.info(f"  🔍 Extracting IP ranges from JSON: {self.source_path}...")
        if not self.source_path.exists():
            logger.error("File not found")
            sys.exit(1)
        
        count = 0
        last_log = time.time()
        
        with open(self.source_path, 'rb') as f:
            for line in f:
                if not line.strip(): 
                    continue
                try:
                    record = json.loads(line)
                    network = record.get('network')
                    if not network: 
                        continue
                    
                    asn_value = record.get('asn')
                    as_name = record.get('as_name')
                    
                    valid_asn = None
                    valid_as_name = None
                    
                    if asn_value:
                        if isinstance(asn_value, int):
                            valid_asn = f"AS{asn_value}"
                            valid_as_name = as_name if as_name else None
                        elif isinstance(asn_value, str):
                            asn_str = asn_value.strip().upper()
                            if asn_str.startswith('AS') and asn_str[2:].isdigit():
                                valid_asn = asn_str
                                valid_as_name = as_name if as_name else None
                    
                    entry = {
                        'country': record.get('country_code'),
                        'country_name': record.get('country'),
                        'city': record.get('city'),
                        'region': record.get('region'),
                        'region_code': record.get('region_code'),
                        'continent': record.get('continent_code'),
                    }
                    
                    if valid_asn:
                        entry['asn'] = valid_asn
                        if valid_as_name:
                            entry['as_name'] = valid_as_name
                    
                    if self.memory_efficient:
                        # Write directly to temp file as binary record
                        record_bytes = json.dumps({'cidr': network, 'info': entry})
                        self._temp_file.write(record_bytes + b'\n')
                    else:
                        self.ip_ranges[network] = entry
                    
                    count += 1
                    
                    if count % 100000 == 0:
                        now = time.time()
                        if now - last_log > 1.0:
                            sys.stdout.write(f"\r     Parsed {count:,} records...")
                            sys.stdout.flush()
                            last_log = now
                except Exception: 
                    continue
        
        sys.stdout.write(f"\r     Parsed {count:,} records... Done.\n")
        
        if self.memory_efficient:
            self._temp_file.flush()

    def _extract_mmdb(self):
        import maxminddb
        import ipaddress
        
        logger.info("  🔍 Extracting IP ranges from MMDB...")
        if not self.source_path.exists():
            logger.error("File not found")
            sys.exit(1)
        
        reader = maxminddb.open_database(str(self.source_path))
        count = 0
        last_log = time.time()
        
        # Optimized IPv4 traversal
        ip_int = 0
        max_val = 2**32
        while ip_int < max_val:
            ip_str = str(ipaddress.IPv4Address(ip_int))
            try:
                record, prefix = reader.get_with_prefix_len(ip_str)
            except ValueError:
                prefix = 32
                record = None
            
            if record:
                self._process_mmdb_record(f"{ip_str}/{prefix}", record)
                count += 1
                
                if count % 20000 == 0:
                    now = time.time()
                    if now - last_log > 1.0:
                        sys.stdout.write(f"\r     Extracted {count:,} records...")
                        sys.stdout.flush()
                        last_log = now
            
            ip_int += 1 << (32 - prefix)
        
        sys.stdout.write(f"\r     Extracted {count:,} records... Done.\n")
        reader.close()
        
        if self.memory_efficient:
            self._temp_file.flush()

    def _process_mmdb_record(self, cidr, data):
        country = None
        if 'country' in data: 
            country = data['country'].get('iso_code')
        elif 'registered_country' in data: 
            country = data['registered_country'].get('iso_code')
        
        region_code = None
        if 'subdivisions' in data and len(data['subdivisions']) > 0:
            region_code = data['subdivisions'][0].get('iso_code')
        
        continent = None
        if 'continent' in data:
            continent = data['continent'].get('code')

        asn_num = None
        as_name = None
        
        if 'autonomous_system_number' in data:
            asn_raw = data['autonomous_system_number']
            if isinstance(asn_raw, int) and asn_raw > 0:
                asn_num = f"AS{asn_raw}"
                
        if 'autonomous_system_organization' in data and asn_num:
            as_name = data['autonomous_system_organization']

        if country or asn_num:
            entry = {
                'country': country,
                'country_name': self.country_names.get(country, country) if country else None,
                'region_code': region_code,
                'continent': continent
            }
            
            if asn_num:
                entry['asn'] = asn_num
                if as_name:
                    entry['as_name'] = as_name
            
            entry = {k: v for k, v in entry.items() if v is not None}
            
            if self.memory_efficient:
                record_bytes = json.dumps({'cidr': cidr, 'info': entry})
                self._temp_file.write(record_bytes + b'\n')
            else:
                self.ip_ranges[cidr] = entry

    def _compute_regions_cached(self, info):
        if self.memory_efficient:
            # No caching in memory-efficient mode
            return self._compute_regions_nocache(info)
        
        key = (
            info.get('country'), 
            info.get('continent'), 
            info.get('city'), 
            info.get('region'), 
            info.get('region_code')
        )
        
        if key in self._region_cache: 
            return self._region_cache[key]
        
        result = self._compute_regions_nocache(info)
        self._region_cache[key] = result
        return result
    
    def _compute_regions_nocache(self, info):
        regions = set()
        cc = info.get('country')

        if cc:
            regions.add(cc.upper())
            
            if cc in self.country_names: 
                regions.add(self.country_names[cc].upper())
            
            continent_code = get_country_continent(cc)
            if continent_code:
                regions.add(continent_code.upper())
                continent_name = get_continent_name(continent_code)
                if continent_name:
                    regions.add(continent_name.upper())
            
            country_regions = get_country_regions(cc)
            for region_name in country_regions:
                regions.add(region_name.upper())

        if info.get('city'): 
            regions.add(info['city'].upper())
        if info.get('region'): 
            regions.add(info['region'].upper())
        if info.get('region_code'): 
            regions.add(info['region_code'].upper())
        if info.get('continent'): 
            regions.add(info['continent'].upper())
        
        return list(regions)

    def _save_binary(self, output_path: str):
        if self.memory_efficient:
            self._save_binary_streaming(output_path)
        else:
            self._save_binary_inmemory(output_path)

    def _save_binary_inmemory(self, output_path: str):
        logger.info(f"  💾 Processing {len(self.ip_ranges)} ranges...")
        ipv4_list, ipv6_list = [], []
        count = 0
        asn_count = 0
        last_log = time.time()
        
        for cidr, info in self.ip_ranges.items():
            count += 1
            if count % 50000 == 0:
                now = time.time()
                if now - last_log > 1.0:
                    sys.stdout.write(f"\r     Processing {count:,}/{len(self.ip_ranges):,}...")
                    sys.stdout.flush()
                    last_log = now
            
            ver, start, end = parse_cidr_fast(cidr)
            if ver == 0: 
                continue
            
            regions = self._compute_regions_cached(info)
            
            cc = info.get('country')
            cont_code = info.get('continent')

            if not cont_code and cc:
                cont_code = get_country_continent(cc)

            cont_name = None
            if cont_code:
                cont_name = get_continent_name(cont_code)
            
            clean_info = {
                'country_code': cc,
                'country_name': info.get('country_name'),
                'continent_code': cont_code,
                'continent_name': cont_name,
                'regions': regions,
                'region_code': info.get('region_code')
            }
            
            if 'asn' in info:
                asn_value = info['asn']
                if asn_value and isinstance(asn_value, str) and asn_value.startswith('AS'):
                    clean_info['asn'] = asn_value
                    asn_count += 1
                    if 'as_name' in info:
                        clean_info['as_name'] = info['as_name']
            
            clean_info = {k: v for k, v in clean_info.items() if v is not None}
            
            if ver == 4: 
                ipv4_list.append((start, end, clean_info))
            elif ver == 6: 
                ipv6_list.append((start, end, clean_info))
        
        sys.stdout.write(f"\r     Processing {count:,}... Done.\n")
        logger.info(f"     ASN records: {asn_count}")
        
        self._write_binary_file(output_path, ipv4_list, ipv6_list)

    def _save_binary_streaming(self, output_path: str):
        logger.info("  💾 Processing ranges (streaming mode)...")
        
        # Close write handle, reopen for reading
        self._temp_file.close()
        
        ipv4_list, ipv6_list = [], []
        count = 0
        asn_count = 0
        last_log = time.time()
        
        with open(self._temp_path, 'rb') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    record = json.loads(line)
                    cidr = record['cidr']
                    info = record['info']
                    
                    count += 1
                    if count % 50000 == 0:
                        now = time.time()
                        if now - last_log > 1.0:
                            sys.stdout.write(f"\r     Processing {count:,}...")
                            sys.stdout.flush()
                            last_log = now
                    
                    ver, start, end = parse_cidr_fast(cidr)
                    if ver == 0: 
                        continue
                    
                    regions = self._compute_regions_nocache(info)
                    
                    cc = info.get('country')
                    cont_code = info.get('continent')

                    if not cont_code and cc:
                        cont_code = get_country_continent(cc)

                    cont_name = None
                    if cont_code:
                        cont_name = get_continent_name(cont_code)
                    
                    clean_info = {
                        'country_code': cc,
                        'country_name': info.get('country_name'),
                        'continent_code': cont_code,
                        'continent_name': cont_name,
                        'regions': regions,
                        'region_code': info.get('region_code')
                    }
                    
                    if 'asn' in info:
                        asn_value = info['asn']
                        if asn_value and isinstance(asn_value, str) and asn_value.startswith('AS'):
                            clean_info['asn'] = asn_value
                            asn_count += 1
                            if 'as_name' in info:
                                clean_info['as_name'] = info['as_name']
                    
                    clean_info = {k: v for k, v in clean_info.items() if v is not None}
                    
                    if ver == 4: 
                        ipv4_list.append((start, end, clean_info))
                    elif ver == 6: 
                        ipv6_list.append((start, end, clean_info))
                        
                except Exception:
                    continue
        
        sys.stdout.write(f"\r     Processing {count:,}... Done.\n")
        logger.info(f"     ASN records: {asn_count}")
        
        # Cleanup temp file
        os.unlink(self._temp_path)
        
        self._write_binary_file(output_path, ipv4_list, ipv6_list)

    def _write_binary_file(self, output_path: str, ipv4_list: list, ipv6_list: list):
        logger.info("     Sorting ranges...")
        ipv4_list.sort(key=lambda x: x[0])
        ipv6_list.sort(key=lambda x: x[0])
        
        logger.info("     Building binary...")
        
        data_cache = {}
        data_buffer = bytearray()
        current_data_offset = 0
        
        def get_data_offset(info_dict):
            nonlocal current_data_offset
            json_bytes = json.dumps(info_dict)
            if json_bytes in data_cache: 
                return data_cache[json_bytes]
            offset = current_data_offset
            data_cache[json_bytes] = offset
            data_buffer.extend(struct.pack('!H', len(json_bytes)))
            data_buffer.extend(json_bytes)
            current_data_offset += 2 + len(json_bytes)
            return offset

        ipv4_index = bytearray()
        ipv4_struct = struct.Struct('!III')
        for start, end, info in ipv4_list:
            offset = get_data_offset(info)
            ipv4_index.extend(ipv4_struct.pack(start, end, offset))

        ipv6_index = bytearray()
        ipv6_struct = struct.Struct('!16s16sI')
        for start, end, info in ipv6_list:
            offset = get_data_offset(info)
            s_bytes = start.to_bytes(16, 'big')
            e_bytes = end.to_bytes(16, 'big')
            ipv6_index.extend(ipv6_struct.pack(s_bytes, e_bytes, offset))

        header = struct.pack('!4sHIIIII6s', 
            b'VIBE', 1, 
            len(ipv4_list), 32, 
            len(ipv6_list), 32 + len(ipv4_index), 
            32 + len(ipv4_index) + len(ipv6_index), 
            b'\x00'*6)
        
        with open(output_path, 'wb') as f:
            f.write(header)
            f.write(ipv4_index)
            f.write(ipv6_index)
            f.write(data_buffer)
        
        size_mb = os.path.getsize(output_path) / (1024*1024)
        logger.info(f"  ✓ Complete! Size: {size_mb:.2f} MB")

    def export_asn_tsv(self, output_path: str):
        logger.info(f"📝 Exporting ASN data to {output_path}")
        
        if self.memory_efficient:
            self._export_asn_streaming(output_path)
        else:
            self._export_asn_inmemory(output_path)

    def _export_asn_inmemory(self, output_path: str):
        asn_data = defaultdict(lambda: {'cidrs': [], 'as_name': ''})
        
        for cidr, info in self.ip_ranges.items():
            if 'asn' in info:
                asn_value = info['asn']
                if asn_value and isinstance(asn_value, str) and asn_value.startswith('AS'):
                    asn_num = asn_value[2:]
                    as_name = info.get('as_name', '')
                
                    asn_data[asn_num]['cidrs'].append(cidr)
                    if as_name and not asn_data[asn_num]['as_name']:
                        asn_data[asn_num]['as_name'] = as_name
        
        for asn_num in asn_data:
            asn_data[asn_num]['cidrs'].sort(key=lambda x: parse_cidr_fast(x)[1])
        
        count = 0
        with open(output_path, 'w', encoding='utf-8') as f:
            for asn_num in sorted(asn_data.keys(), key=int):
                as_name = asn_data[asn_num]['as_name']
                for cidr in asn_data[asn_num]['cidrs']:
                    f.write(f"{cidr}\t{asn_num}\t{as_name}\n")
                    count += 1
        
        logger.info(f"✓ Exported {count} entries for {len(asn_data)} ASNs")

    def _export_asn_streaming(self, output_path: str):
        asn_data = defaultdict(lambda: {'cidrs': [], 'as_name': ''})
        
        with open(self._temp_path, 'rb') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    cidr = record['cidr']
                    info = record['info']
                    
                    if 'asn' in info:
                        asn_value = info['asn']
                        if asn_value and isinstance(asn_value, str) and asn_value.startswith('AS'):
                            asn_num = asn_value[2:]
                            as_name = info.get('as_name', '')
                        
                            asn_data[asn_num]['cidrs'].append(cidr)
                            if as_name and not asn_data[asn_num]['as_name']:
                                asn_data[asn_num]['as_name'] = as_name
                except Exception:
                    continue
        
        for asn_num in asn_data:
            asn_data[asn_num]['cidrs'].sort(key=lambda x: parse_cidr_fast(x)[1])
        
        count = 0
        with open(output_path, 'w', encoding='utf-8') as f:
            for asn_num in sorted(asn_data.keys(), key=int):
                as_name = asn_data[asn_num]['as_name']
                for cidr in asn_data[asn_num]['cidrs']:
                    f.write(f"{cidr}\t{asn_num}\t{as_name}\n")
                    count += 1
        
        logger.info(f"✓ Exported {count} entries for {len(asn_data)} ASNs")

    def compile(self, output_path: str = "geoip.vibe"):
        self.extract()
        self._save_binary(output_path)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="GeoIP Binary Compiler")
    parser.add_argument("--mmdb", help="Path to MaxMind .mmdb file")
    parser.add_argument("--json", help="Path to JSON source file (NDJSON)")
    parser.add_argument("--unified-output", default="geoip.vibe", help="Output file path")
    parser.add_argument("--skip-geonames", action="store_true", help="Skip downloading GeoNames")
    parser.add_argument("--export-rules", help="Export rule reference to text file")
    parser.add_argument("--export-asn", help="Export ASN data to TSV file (IPASN format)")
    parser.add_argument("--memory-efficient", action="store_true", 
                        help="Use memory-efficient mode (slower but uses less RAM)")
    args = parser.parse_args()
    
    gc = GeoNamesCompiler()
    if not args.skip_geonames: 
        gc.compile_geonames()
    else: 
        gc.compile_geonames()
    
    if args.export_rules:
        gc.export_rules_text(args.export_rules)
        if not args.mmdb and not args.json:
            return

    if not args.mmdb and not args.json:
        if not args.export_rules:
            parser.print_help()
        return

    source = args.mmdb if args.mmdb else args.json
    stype = 'mmdb' if args.mmdb else 'json'
    uc = UnifiedGeoIPCompiler(source, stype, gc, memory_efficient=args.memory_efficient)
    uc.compile(args.unified_output)
    
    if args.export_asn:
        uc.export_asn_tsv(args.export_asn)

if __name__ == "__main__":
    main()

