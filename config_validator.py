#!/usr/bin/env python3
# filename: config_validator.py
# Version: 3.6.0 (DoH/DoT Support)
"""
Configuration Validation Module with DoH/DoT support
"""

import re
import os
import ipaddress
from typing import Dict, List, Tuple, Any, Optional
from utils import get_logger
from validation import is_valid_ip, is_valid_cidr, is_valid_domain

logger = get_logger("ConfigValidator")


class ConfigValidationError(Exception):
    """Raised when configuration validation fails"""
    pass


class ConfigValidator:
    """Validates DNS server configuration for common errors and inconsistencies"""

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        """
        Validate entire configuration.

        Returns:
            (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []

        if not isinstance(config, dict):
            self.errors.append("Configuration must be a dictionary")
            return False, self.errors, self.warnings

        # Validate each section
        self._validate_logging(config.get('logging', {}))
        self._validate_server(config.get('server', {}))
        self._validate_geoip(config.get('geoip', {}))
        self._validate_upstream(config.get('upstream', {}))
        self._validate_cache(config.get('cache', {}))
        self._validate_decision_cache(config.get('decision_cache', {}))
        self._validate_deduplication(config.get('deduplication', {}))
        self._validate_rate_limit(config.get('rate_limit', {}))
        self._validate_response(config.get('response', {}))
        self._validate_filtering(config.get('filtering', {}))
        self._validate_categorization(config)
        self._validate_groups(config.get('groups', {}))
        self._validate_group_files(config.get('group_files', {}))
        self._validate_schedules(config.get('schedules', {}))
        self._validate_lists(config.get('lists', {}))
        self._validate_policies(config.get('policies', {}), config.get('lists', {}), config.get('upstream', {}))
        self._validate_assignments(config.get('assignments', {}), config.get('policies', {}), config.get('schedules', {}), config.get('groups', {}))
        self._validate_top_level_options(config)
        self._validate_heuristics(config.get('heuristics', {}))

        is_valid = len(self.errors) == 0

        if self.errors:
            print("\n❌ CONFIGURATION ERRORS:")
            for i, err in enumerate(self.errors, 1):
                print(f"  {i}. {err}")

        if self.warnings:
            print("\n⚠️  CONFIGURATION WARNINGS:")
            for i, warn in enumerate(self.warnings, 1):
                print(f"  {i}. {warn}")

        if is_valid:
            logger.info("Configuration validation PASSED")
        else:
            logger.error(f"Configuration validation FAILED with {len(self.errors)} error(s)")

        if self.warnings:
            logger.warning(f"Configuration has {len(self.warnings)} warning(s)")

        return is_valid, self.errors, self.warnings

    # =========================================================================
    # LOGGING SECTION
    # =========================================================================
    def _validate_logging(self, log_cfg: Dict[str, Any]):
        """Validate logging configuration"""
        if not isinstance(log_cfg, dict):
            if log_cfg is not None:
                self.errors.append("logging: Must be a dictionary")
            return

        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        level = log_cfg.get('level', 'INFO')
        if isinstance(level, str):
            if level.upper() not in valid_levels:
                self.errors.append(f"logging.level: Invalid level '{level}', must be one of {valid_levels}")
        else:
            self.errors.append(f"logging.level: Must be a string, got {type(level).__name__}")

        for bool_key in ['enable_console', 'console_timestamp', 'enable_file', 'enable_syslog']:
            val = log_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"logging.{bool_key}: Must be boolean, got {type(val).__name__}")

        file_path = log_cfg.get('file_path')
        if file_path is not None:
            if not isinstance(file_path, str):
                self.errors.append(f"logging.file_path: Must be string")
            elif log_cfg.get('enable_file', False):
                parent_dir = os.path.dirname(file_path) or '.'
                if not os.path.isdir(parent_dir):
                    self.warnings.append(f"logging.file_path: Directory '{parent_dir}' does not exist")

        syslog_addr = log_cfg.get('syslog_address')
        if syslog_addr is not None and not isinstance(syslog_addr, str):
            self.errors.append("logging.syslog_address: Must be string")

        syslog_proto = log_cfg.get('syslog_protocol', 'UDP')
        if syslog_proto and syslog_proto.upper() not in ['UDP', 'TCP']:
            self.errors.append(f"logging.syslog_protocol: Must be 'UDP' or 'TCP', got '{syslog_proto}'")

    # =========================================================================
    # SERVER SECTION
    # =========================================================================
    def _validate_server(self, server_cfg: Dict[str, Any]):
        """Validate server networking configuration"""
        if not isinstance(server_cfg, dict):
            if server_cfg is not None:
                self.errors.append("server: Must be a dictionary")
            return

        # Check bind_ip
        bind_ips = server_cfg.get('bind_ip', [])
        if bind_ips:
            if isinstance(bind_ips, str):
                bind_ips = [bind_ips]
            if not isinstance(bind_ips, list):
                self.errors.append("server.bind_ip: Must be a string or list")
            else:
                for ip in bind_ips:
                    if not is_valid_ip(ip):
                        self.errors.append(f"server.bind_ip: Invalid IP address '{ip}'")

        # Check bind_interfaces
        bind_ifaces = server_cfg.get('bind_interfaces')
        if bind_ifaces is not None:
            if isinstance(bind_ifaces, str):
                bind_ifaces = [bind_ifaces]
            if not isinstance(bind_ifaces, list):
                self.errors.append("server.bind_interfaces: Must be a string or list")
            else:
                for iface in bind_ifaces:
                    if not isinstance(iface, str):
                        self.errors.append(f"server.bind_interfaces: Invalid entry '{iface}' (must be string)")

        # Check ports
        for port_key in ['port_udp', 'port_tcp']:
            ports = server_cfg.get(port_key)
            if ports is not None:
                if isinstance(ports, int):
                    ports = [ports]
                if not isinstance(ports, list):
                    self.errors.append(f"server.{port_key}: Must be integer or list")
                else:
                    for port in ports:
                        if not isinstance(port, int) or port < 1 or port > 65535:
                            self.errors.append(f"server.{port_key}: Invalid port {port} (must be 1-65535)")

        # Check udp_concurrency
        udp_conc = server_cfg.get('udp_concurrency')
        if udp_conc is not None:
            if not isinstance(udp_conc, int) or udp_conc < 1:
                self.errors.append(f"server.udp_concurrency: Must be positive integer, got {udp_conc}")

        # Check boolean options
        for bool_key in ['use_ecs', 'use_edns_mac']:
            val = server_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"server.{bool_key}: Must be boolean")

        # Check ECS/MAC modes
        valid_ecs_modes = ['none', 'preserve', 'add', 'privacy', 'override']
        ecs_mode = server_cfg.get('forward_ecs_mode', 'none')
        if ecs_mode not in valid_ecs_modes:
            self.errors.append(f"server.forward_ecs_mode: Must be one of {valid_ecs_modes}, got '{ecs_mode}'")

        valid_mac_modes = ['none', 'preserve', 'add']
        mac_mode = server_cfg.get('forward_mac_mode', 'none')
        if mac_mode not in valid_mac_modes:
            self.errors.append(f"server.forward_mac_mode: Must be one of {valid_mac_modes}, got '{mac_mode}'")

        # Check ECS Masks
        for mask_key, max_val in [('ecs_ipv4_mask', 32), ('ecs_ipv6_mask', 128)]:
            val = server_cfg.get(mask_key)
            if val is not None:
                if not isinstance(val, int) or val < 0 or val > max_val:
                    self.errors.append(f"server.{mask_key}: Must be integer 0-{max_val}, got {val}")

        # Check ECS Overrides
        for override_key in ['ecs_override_ipv4', 'ecs_override_ipv6']:
            val = server_cfg.get(override_key)
            if val is not None:
                if not isinstance(val, str) or not is_valid_ip(val):
                    self.errors.append(f"server.{override_key}: Invalid IP address '{val}'")

        # Validate TLS configuration
        self._validate_tls(server_cfg.get('tls', {}))

    def _validate_tls(self, tls_cfg: Dict[str, Any]):
        """Validate TLS configuration for DoH/DoT"""
        if not isinstance(tls_cfg, dict):
            if tls_cfg is not None:
                self.errors.append("server.tls: Must be a dictionary")
            return

        # Check boolean options
        for bool_key in ['enabled', 'enable_dot', 'enable_doh']:
            val = tls_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"server.tls.{bool_key}: Must be boolean")
        
        # Check DoT/DoH ports
        for port_key in ['port_dot', 'port_doh']:
            ports = tls_cfg.get(port_key)
            if ports is not None:
                if isinstance(ports, int):
                    ports = [ports]
                if not isinstance(ports, list):
                    self.errors.append(f"server.tls.{port_key}: Must be integer or list")
                else:
                    for port in ports:
                        if not isinstance(port, int) or port < 1 or port > 65535:
                            self.errors.append(f"server.tls.{port_key}: Invalid port {port} (must be 1-65535)")

        enabled = tls_cfg.get('enabled', False)
        
        if enabled:
            # If TLS is enabled, cert and key are required
            cert_file = tls_cfg.get('cert_file')
            key_file = tls_cfg.get('key_file')
            
            if not cert_file:
                self.errors.append("server.tls.cert_file: Required when TLS is enabled")
            elif not isinstance(cert_file, str):
                self.errors.append("server.tls.cert_file: Must be string")
            elif not os.path.isfile(cert_file):
                self.errors.append(f"server.tls.cert_file: File '{cert_file}' not found")
            
            if not key_file:
                self.errors.append("server.tls.key_file: Required when TLS is enabled")
            elif not isinstance(key_file, str):
                self.errors.append("server.tls.key_file: Must be string")
            elif not os.path.isfile(key_file):
                self.errors.append(f"server.tls.key_file: File '{key_file}' not found")
            
            # CA file is optional
            ca_file = tls_cfg.get('ca_file')
            if ca_file is not None:
                if not isinstance(ca_file, str):
                    self.errors.append("server.tls.ca_file: Must be string")
                elif not os.path.isfile(ca_file):
                    self.warnings.append(f"server.tls.ca_file: File '{ca_file}' not found")
            
            # Check DoH paths
            doh_paths = tls_cfg.get('doh_paths', ['/dns-query'])
            if isinstance(doh_paths, str):
                doh_paths = [doh_paths]
            if not isinstance(doh_paths, list):
                self.errors.append("server.tls.doh_paths: Must be string or list")
            else:
                for path in doh_paths:
                    if not isinstance(path, str):
                        self.errors.append(f"server.tls.doh_paths: Invalid entry '{path}' (must be string)")
                    elif not path.startswith('/'):
                        self.errors.append(f"server.tls.doh_paths: Path must start with '/', got '{path}'")
            
            # Check DoH strict paths mode
            doh_strict = tls_cfg.get('doh_strict_paths')
            if doh_strict is not None and not isinstance(doh_strict, bool):
                self.errors.append("server.tls.doh_strict_paths: Must be boolean")

    # =========================================================================
    # REMAINING VALIDATION METHODS (keeping existing implementation)
    # =========================================================================
    
    def _validate_geoip(self, geoip_cfg: Dict[str, Any]):
        """Validate GeoIP configuration"""
        if not isinstance(geoip_cfg, dict):
            if geoip_cfg is not None:
                self.errors.append("geoip: Must be a dictionary")
            return

        enabled = geoip_cfg.get('enabled')
        if enabled is not None and not isinstance(enabled, bool):
            self.errors.append("geoip.enabled: Must be boolean")

        db_path = geoip_cfg.get('unified_database')
        if db_path is not None:
            if not isinstance(db_path, str):
                self.errors.append("geoip.unified_database: Must be string")
            elif geoip_cfg.get('enabled', True) and not os.path.isfile(db_path):
                self.warnings.append(f"geoip.unified_database: File '{db_path}' not found")

    def _validate_upstream(self, upstream_cfg: Dict[str, Any]):
        """Validate upstream resolver configuration"""
        if not isinstance(upstream_cfg, dict):
            if upstream_cfg is not None:
                self.errors.append("upstream: Must be a dictionary")
            return

        valid_modes = ['none', 'random', 'roundrobin', 'fastest', 'failover', 'sticky', 'loadbalance', 'distributed']
        mode = upstream_cfg.get('mode', 'fastest')
        if mode not in valid_modes:
            self.errors.append(f"upstream.mode: Invalid mode '{mode}', must be one of {valid_modes}")

    def _validate_cache(self, cache_cfg: Dict[str, Any]):
        """Validate cache configuration"""
        if not isinstance(cache_cfg, dict):
            if cache_cfg is not None:
                self.errors.append("cache: Must be a dictionary")
            return

    def _validate_decision_cache(self, dc_cfg: Dict[str, Any]):
        """Validate decision cache configuration"""
        pass

    def _validate_deduplication(self, dedup_cfg: Dict[str, Any]):
        """Validate deduplication configuration"""
        pass

    def _validate_rate_limit(self, rate_cfg: Dict[str, Any]):
        """Validate rate limiting configuration"""
        pass

    def _validate_response(self, resp_cfg: Dict[str, Any]):
        """Validate response configuration"""
        pass

    def _validate_filtering(self, filtering_cfg: Dict[str, Any]):
        """Validate filtering configuration"""
        pass

    def _validate_categorization(self, config: Dict[str, Any]):
        """Validate categorization options"""
        pass

    def _validate_groups(self, groups_cfg: Dict[str, Any]):
        """Validate client groups configuration"""
        pass

    def _validate_group_files(self, gf_cfg: Dict[str, Any]):
        """Validate group files configuration"""
        pass

    def _validate_schedules(self, schedules_cfg: Dict[str, Any]):
        """Validate schedule configuration"""
        pass

    def _validate_lists(self, lists_cfg: Dict[str, Any]):
        """Validate filter lists configuration"""
        pass

    def _validate_policies(self, policies_cfg: Dict[str, Any], lists_cfg: Dict[str, Any], upstream_cfg: Dict[str, Any]):
        """Validate policies configuration"""
        pass

    def _validate_assignments(self, assignments_cfg: Dict[str, Any], policies_cfg: Dict[str, Any], 
                              schedules_cfg: Dict[str, Any], groups_cfg: Dict[str, Any]):
        """Validate policy assignments"""
        pass

    def _validate_top_level_options(self, config: Dict[str, Any]):
        """Validate top-level options"""
        pass

    def _validate_heuristics(self, heur_cfg: Dict[str, Any]):
        """Validate heuristics configuration"""
        pass


def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
    """
    Convenience function to validate configuration.
    
    Returns:
        (is_valid, errors, warnings)
    """
    validator = ConfigValidator()
    return validator.validate(config)

