# VIBE-DNS

**VIBE-DNS** is a high-performance, policy-driven filtering DNS server written in Python. It provides enterprise-grade control over DNS traffic with support for modern protocols (DoH/DoT), granular client identification, and advanced filtering logic.

It is designed to be a "single source of truth" for network DNS, capable of handling complex routing and blocking scenarios.

## 🚀 Key Features

### 🛡️ Advanced Filtering Engine
* **Multi-Layer Rules:** Block or allow based on **Domains** (exact/wildcard), **Regex**, **IP/CIDR** ranges, and **GeoIP** tags.
* **Query & Answer Filtering:**
    * Filter based on the domain being queried.
    * Filter based on the **IP addresses returned** in the answer (e.g., block domains hosting malware on specific subnets).
    * **CNAME Traversal:** Recursively checks CNAME targets against blocklists.
* **Categorization:** Built-in engine to classify domains (e.g., *Gambling, Adult, Tracking*) with confidence scoring and configurable thresholds.
* **Action Types:** `BLOCK` (Refused/NXDOMAIN/Sinkhole), `ALLOW` (Bypass), and `DROP` (Silent timeout).

### 🌍 GeoIP & Location Control
* **High-Performance DB:** Uses a custom memory-mapped binary database for O(log n) lookups.
* **Dual-Mode Blocking:**
    * `@REGION`: Blocks based on the **TLD** of the query (e.g., `.cn`).
    * `@@REGION`: Blocks based on the **IP location** of the resolved answer.
* **Granularity:** Filter by Continent (e.g., `@@EUROPE`), Region (e.g., `@@EU_MEMBERS`), or Country (e.g., `@@US`).

### ⚡ Upstream Management
* **Protocols:** Supports **UDP**, **TCP**, **DoT** (DNS over TLS), and **DoH** (DNS over HTTPS/2).
* **Strategies:**
    * `fastest`: Probes latency and uses the quickest responder.
    * `sticky`: Pins a client to a specific upstream for session consistency.
    * `loadbalance`, `failover`, `random`, `roundrobin`.
* **Resilience:** Integrated **Circuit Breaker** to temporarily stop querying failing upstreams and background health monitoring.

### 🎯 Client Identification & Groups
* Identify clients via:
    * **Source IP / CIDR Subnet**
    * **MAC Address** (via local ARP table or EDNS0 options).
    * **Server Interface:** Identify based on which IP/Port the query arrived on (useful for VLANs).
    * **GeoIP Tag:** Apply rules based on the client's physical location.
* **Policies:** Map Groups to Policies. Policies define which blocklists, allowlists, and upstream servers are used.
* **Schedules:** Apply time-based policies (e.g., stricter filtering during "Bedtime").

### ⚡ Performance & Caching
* **LRU Cache:** High-speed in-memory cache with **Optimistic Prefetching** (refreshes popular records before they expire).
* **Request Deduplication:** Merges identical concurrent queries into a single upstream request to prevent thundering herds.
* **Decision Cache:** Caches policy results (Block/Allow decisions) to bypass the rule engine for frequent queries.

### 🔧 Response Modification
* **CNAME Flattening:** Can remove intermediate CNAME chains and return only the final A/AAAA record.
* **TTL Normalization:** Enforce min/max TTLs or sync TTLs across records.
* **Round Robin:** Randomize A/AAAA record order for client-side load balancing.
* **Rate Limiting:** DoS protection with per-subnet request windows and automatic fallback to TCP (truncation) or dropping.

## 🛠️ Installation & Usage

**Requirements:** Python 3.14+ (Recommended) and dependencies listed in `requirements.txt`.

### 1. Setup Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
````

### 2\. Compile GeoIP Database

Vibe-DNS uses a custom binary format. You must compile it from MaxMind or JSON sources before enabling GeoIP.

```bash
# Example using a downloaded JSON source
python3 geoip_compiler.py --json ipinfo_lite.json --unified-output geoip.vibe
```

### 3\. Configuration

Copy `full_config.yaml` to `config.yaml` and edit to suit your network.

  * Define **Lists** (local files or remote URLs).
  * Define **Groups** (your clients).
  * Define **Policies** (combining lists and upstreams).
  * Assign Groups to Policies.

### 4\. Run Server

```bash
python3 server.py --config config.yaml
```

## 📂 Project Structure

  * `server.py`: Main entry point, handles UDP/TCP listeners and concurrency.
  * `resolver.py`: Core logic for query processing, caching, and policy enforcement.
  * `filtering.py`: Rule matching engine (Trie/Regex/IntervalTree).
  * `upstream_manager.py`: Handles upstream connections (DoH/DoT/UDP) and load balancing.
  * `geoip.py` & `geoip_compiler.py`: Runtime lookup and database compilation tools.
  * `list_manager.py`: Fetches and parses blocklists/allowlists.
  * `config_validator.py`: Ensures configuration integrity at startup.

## ⚠️ Disclaimer

This is a testing project. Use at your own risk. While designed for performance and security, it is not an official enterprise product.
