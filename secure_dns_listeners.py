#!/usr/bin/env python3
"""
DNS over HTTPS (DoH) and DNS over TLS (DoT) Listeners
RFC 8484 (DoH) and RFC 7858 (DoT)
"""

import asyncio
import ssl
import logging
from typing import Optional, List, Union
from urllib.parse import urlparse, parse_qs

from utils import get_logger

logger = get_logger("SecureDNS")


class DoTServer:
    """DNS over TLS (RFC 7858) - Port 853"""
    def __init__(self, handler, host, port):
        self.handler = handler
        self.host = host
        self.port = port

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        if not addr:
            # Cannot identify peer, abort
            writer.close()
            return

        ssl_obj = writer.get_extra_info('ssl_object')
        
        # Extract TLS info
        tls_version = None
        cipher = None
        sni = None
        
        if ssl_obj:
            tls_version = ssl_obj.version()
            cipher = ssl_obj.cipher()
            try:
                # Try custom attribute from callback first, then standard attribute
                sni = getattr(ssl_obj, "vibe_sni", None) or getattr(ssl_obj, "server_hostname", None)
            except Exception:
                pass
        
        logger.info(f"DoT Connection from {addr[0]}:{addr[1]} on {self.host}:{self.port} "
                   f"(TLS: {tls_version}, Cipher: {cipher[0] if cipher else 'Unknown'}, SNI: {sni})")
        
        meta = {
            'proto': 'dot',
            'server_ip': self.host,
            'server_port': self.port,
            'sni': sni
        }
        
        queries_handled = 0
        
        try:
            while True:
                try:
                    # Read length (2 bytes)
                    len_bytes = await reader.readexactly(2)
                    length = int.from_bytes(len_bytes, 'big')
                    
                    # Read Query
                    data = await reader.readexactly(length)
                    
                    # Process
                    resp = await self.handler.process_query(data, addr, meta)
                    
                    if resp:
                        # Write response length + response
                        writer.write(len(resp).to_bytes(2, 'big') + resp)
                        await writer.drain()
                        queries_handled += 1
                    else:
                        # Handler dropped query, but keep connection open
                        pass
                        
                except asyncio.IncompleteReadError:
                    # Connection closed by client
                    break
                
        except ssl.SSLError as e:
            logger.warning(f"DoT {addr[0]}:{addr[1]} - SSL Error: {e}")
        except Exception as e:
            logger.error(f"DoT {addr[0]}:{addr[1]} - Error: {e}", exc_info=True)
        finally:
            logger.info(f"DoT {addr[0]}:{addr[1]} - Session closed "
                       f"(Queries: {queries_handled})")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                pass


class DoHServer:
    """DNS over HTTPS (RFC 8484) - HTTP/2 ONLY"""
    def __init__(self, handler, host, port, paths: Union[List[str], str, None] = None, strict_paths: bool = False):
        self.handler = handler
        self.host = host
        self.port = port
        
        # Normalize and validate paths
        if paths is None:
            self.paths = {'/dns-query'}
        elif isinstance(paths, str):
            self.paths = {paths.strip()}
        else:
            self.paths = {p.strip() for p in paths if p and p.strip()}
            
        self.strict_paths = strict_paths
        
        # Ensure fallback if empty
        if not self.paths:
            self.paths = {'/dns-query'}
            
        logger.debug(f"DoH Initialized: strict_paths={self.strict_paths}, allowed_paths={self.paths}")

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        if not addr:
            writer.close()
            return

        ssl_obj = writer.get_extra_info('ssl_object')
        
        # Extract TLS info
        tls_version = None
        cipher = None
        alpn_protocol = None
        sni = None
        
        if ssl_obj:
            tls_version = ssl_obj.version()
            cipher = ssl_obj.cipher()
            try:
                alpn_protocol = ssl_obj.selected_alpn_protocol()
            except:
                pass
            try:
                # Try custom attribute from callback first, then standard attribute
                sni = getattr(ssl_obj, "vibe_sni", None) or getattr(ssl_obj, "server_hostname", None)
            except:
                pass
        
        # Require HTTP/2
        if alpn_protocol != 'h2':
            logger.warning(f"DoH {addr[0]}:{addr[1]} - HTTP/2 required but client negotiated: {alpn_protocol or 'http/1.1'}")
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return
        
        logger.info(f"DoH Connection from {addr[0]}:{addr[1]} on {self.host}:{self.port} "
                   f"(TLS: {tls_version}, Cipher: {cipher[0] if cipher else 'Unknown'}, ALPN: h2, SNI: {sni})")
        
        try:
            # Import h2 library
            try:
                from h2.connection import H2Connection
                from h2.events import (
                    RequestReceived, DataReceived, StreamEnded,
                    ConnectionTerminated, StreamReset
                )
                from h2.config import H2Configuration
            except ImportError:
                logger.error("h2 library not installed. Install with: pip install h2")
                writer.close()
                await writer.wait_closed()
                return
            
            import time
            import base64
            
            # Initialize HTTP/2 connection
            config = H2Configuration(client_side=False)
            h2_conn = H2Connection(config=config)
            h2_conn.initiate_connection()
            writer.write(h2_conn.data_to_send())
            await writer.drain()
            
            # Track active streams
            streams = {}
            session_start = time.time()
            queries_handled = 0
            bytes_received = 0
            bytes_sent = 0
            
            meta = {
                'proto': 'doh',
                'server_ip': self.host,
                'server_port': self.port,
                'sni': sni
            }
            
            while True:
                # Read data from client
                try:
                    data = await reader.read(65535)
                except Exception:
                    break

                if not data:
                    break
                
                bytes_received += len(data)
                events = h2_conn.receive_data(data)
                
                for event in events:
                    if isinstance(event, RequestReceived):
                        # New request on stream
                        stream_id = event.stream_id
                        headers_dict = dict(event.headers)
                        
                        method = headers_dict.get(b':method', b'').decode('utf-8')
                        path = headers_dict.get(b':path', b'').decode('utf-8')
                        authority = headers_dict.get(b':authority', b'').decode('utf-8')
                        
                        logger.debug(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: {method} {path}")
                        
                        streams[stream_id] = {
                            'method': method,
                            'path': path,
                            'authority': authority,
                            'headers': headers_dict,
                            'data': b'',
                            'start_time': time.time()
                        }
                    
                    elif isinstance(event, DataReceived):
                        # Request body data
                        stream_id = event.stream_id
                        if stream_id in streams:
                            streams[stream_id]['data'] += event.data
                    
                    elif isinstance(event, StreamEnded):
                        # Request complete, process it
                        stream_id = event.stream_id
                        if stream_id not in streams:
                            continue
                        
                        stream_info = streams[stream_id]
                        method = stream_info['method']
                        path = stream_info['path']
                        request_data = stream_info['data']
                        
                        # Parse path
                        parsed = urlparse(path)
                        request_path = parsed.path
                        
                        # Validate path
                        if request_path not in self.paths:
                            if self.strict_paths:
                                logger.warning(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: Path rejected. Requested: '{request_path}'")
                                response_headers = [(':status', '404')]
                                h2_conn.send_headers(stream_id, response_headers)
                                h2_conn.send_data(stream_id, b'Not Found', end_stream=True)
                                writer.write(h2_conn.data_to_send())
                                await writer.drain()
                                del streams[stream_id]
                                continue
                        
                        dns_data = None
                        
                        if method == 'GET':
                            # GET: dns= parameter in base64url
                            params = parse_qs(parsed.query)
                            if 'dns' in params:
                                try:
                                    b64_data = params['dns'][0]
                                    missing_padding = len(b64_data) % 4
                                    if missing_padding:
                                        b64_data += '=' * (4 - missing_padding)
                                    dns_data = base64.urlsafe_b64decode(b64_data)
                                except Exception:
                                    pass
                        
                        elif method == 'POST':
                            dns_data = request_data
                        
                        if not dns_data:
                            response_headers = [(':status', '400')]
                            h2_conn.send_headers(stream_id, response_headers)
                            h2_conn.send_data(stream_id, b'Bad Request', end_stream=True)
                            writer.write(h2_conn.data_to_send())
                            await writer.drain()
                            del streams[stream_id]
                            continue
                        
                        # Process DNS query
                        req_meta = meta.copy()
                        req_meta['doh_path'] = request_path

                        dns_response = await self.handler.process_query(dns_data, addr, req_meta)
                        
                        if dns_response:
                            # Send response
                            response_headers = [
                                (':status', '200'),
                                ('content-type', 'application/dns-message'),
                                ('content-length', str(len(dns_response))),
                                ('cache-control', 'max-age=0'),
                            ]
                            h2_conn.send_headers(stream_id, response_headers)
                            h2_conn.send_data(stream_id, dns_response, end_stream=True)
                            
                            data_to_send = h2_conn.data_to_send()
                            writer.write(data_to_send)
                            await writer.drain()
                            bytes_sent += len(data_to_send)
                            queries_handled += 1
                        else:
                            # 500 Error if handler returns None
                            response_headers = [(':status', '500')]
                            h2_conn.send_headers(stream_id, response_headers)
                            h2_conn.send_data(stream_id, b'Internal Error', end_stream=True)
                            writer.write(h2_conn.data_to_send())
                            await writer.drain()
                        
                        del streams[stream_id]
                    
                    elif isinstance(event, ConnectionTerminated):
                        break
                    
                    elif isinstance(event, StreamReset):
                        stream_id = event.stream_id
                        if stream_id in streams:
                            del streams[stream_id]
                
                # Send any pending data (e.g. window updates)
                data_to_send = h2_conn.data_to_send()
                if data_to_send:
                    writer.write(data_to_send)
                    await writer.drain()
            
            session_duration = time.time() - session_start
            logger.info(f"DoH {addr[0]}:{addr[1]} - Session closed (Queries: {queries_handled}, Duration: {session_duration:.2f}s)")
        
        except Exception as e:
            logger.error(f"DoH {addr[0]}:{addr[1]} - Error: {e}", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def create_ssl_context(cert_file: str, key_file: str, ca_file: Optional[str] = None) -> ssl.SSLContext:
    """Create SSL context for DoT/DoH with explicit SNI capture"""
    logger.info(f"Creating SSL context (Cert: {cert_file}, Key: {key_file})")
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    try:
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    except Exception as e:
        logger.error(f"✗ Failed to load certificate chain: {e}")
        raise
    
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.verify_mode = ssl.CERT_NONE
    
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    # Enable H2 negotiation for DoH, but be compatible with DoT
    context.set_alpn_protocols(['h2', 'http/1.1', 'dot'])
    
    # --- SNI Callback to ensure extraction ---
    def sni_callback(ssl_obj, server_name, ctx):
        # Store SNI on the SSL object for retrieval in handlers
        setattr(ssl_obj, "vibe_sni", server_name)
    
    context.sni_callback = sni_callback
    
    return context

