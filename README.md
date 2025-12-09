# VIBE-DNS

**VIBE-DNS** is a high-performance, policy-driven filtering DNS server written in Python. Designed as a "single source of truth" for network DNS, it provides enterprise-grade control over traffic with support for modern protocols (DoH/DoT), granular client identification, and advanced filtering logic.

It is engineered to handle complex routing scenarios, including those behind proxies or NATs, by leveraging advanced protocol features like EDNS Client Subnet (ECS).

---

## 🚀 Key Features Overview

### 🛡️ Advanced Filtering Engine
* **Multi-Layer Rules:** Block or allow based on **Domains** (exact/wildcard), **Regex**, **IP/CIDR** ranges, and **GeoIP** tags.
* **Deep Inspection:**
    * **Query Filtering:** Blocks requests before they are resolved based on the domain name.
    * **Answer Filtering:** Inspects the **resolved IP addresses** and **CNAME targets** returned by upstream servers. If a safe domain resolves to a malicious IP or blocked CNAME, the entire response is blocked.
* **Categorization:** Built-in engine classifies domains (e.g., *Gambling, Adult, Tracking*) using keyword matching and regex patterns with confidence scoring.

### 🌍 GeoIP & Location Control
* **Dual-Mode Blocking:**
    * **`@REGION` (Query-Side):** Blocks based on the **ccTLD** of the query (e.g., querying `.ru` blocks if Russia is restricted).
    * **`@@REGION` (Answer-Side):** Blocks based on the **physical IP location** of the resolved server.
* **Granularity:** Support for Continents (`@@EUROPE`), Political Unions (`@@EU_MEMBERS`), Regions (`@@ASEAN`), and Countries (`@@US`).

### ⚡ Upstream Management & Resiliency
* **Protocols:** UDP, TCP, **DoT** (DNS over TLS), and **DoH** (DNS over HTTPS/2).
* **Smart Routing:**
    * **`fastest`**: Probes latency and selects the quickest responder.
    * **`sticky`**: Pins a client to a specific upstream for session consistency.
    * **Circuit Breaker**: Automatically stops querying failing upstreams and tests them in the background before reintegration.

---

## 🔍 Deep Dive: Client Identification

VIBE-DNS uses a priority-based system to identify *who* is making a query. This allows you to apply different policies (e.g., "Kids," "IoT," "Guest") to different devices.

### 1. EDNS Client Subnet (ECS) Support
This is the primary method for identifying clients located behind intermediaries like NAT gateways, VPN concentrators, or other DNS forwarders.

* **How it works:** If a query includes the ECS option (RFC 7871), VIBE-DNS extracts the subnet provided in the packet.
* **Precedence:** The ECS IP takes **precedence** over the source IP address. If `use_ecs: true` is configured, the server uses the IP inside the ECS option to map the client to a Group.
* **Use Case:** Essential for environments where VIBE-DNS sits behind a recursive resolver or load balancer that masks the original client IP.

### 2. Source IP & MAC Address
* **Source IP:** The standard method for direct LAN clients. Supports individual IPs or CIDR subnets (e.g., `192.168.1.0/24`).
* **MAC Address:**
    * **Native:** Resolves IPs to MAC addresses using the local system's ARP/Neighbor table.
    * **EDNS0 MAC:** Supports custom EDNS option (Code 65001) for forwarding MAC addresses across network boundaries.

### 3. Interface Binding (VLAN Support)
* **Server IP/Port:** You can identify clients based on *where* the packet arrived.
    * Example: All traffic arriving on `10.0.50.1` (a specific VLAN gateway IP) can be automatically assigned to the "IoT_Policy" group.

---

## 📡 Traffic Handling & Privacy

VIBE-DNS gives you granular control over what data is sent upstream.

### ECS Forwarding Modes
Configured via `forward_ecs_mode` in `config.yaml`:
* **`none` (Privacy Mode):** Strips ECS data from the query before forwarding to upstream resolvers. This hides your internal network topology from public resolvers like Google or Cloudflare.
* **`preserve` (Transparent):** Forwards the client's original ECS data exactly as received. Useful if VIBE-DNS is an intermediate hop.
* **`add` (Injection):** Injects the client's actual source IP as an ECS option into the upstream query. This allows the upstream resolver to optimize the response for the client's location.

### Response Modification
* **CNAME Flattening:** Recursively resolves CNAME chains and returns only the final A/AAAA record, reducing packet size and latency.
* **TTL Normalization:** Enforce specific Min/Max TTLs or synchronize TTLs across all records in a response to prevent cache poisoning or evasion.
* **Round Robin:** Randomizes the order of A/AAAA records to ensure basic load balancing for client applications.

---

## 🛠️ Installation

**Prerequisites:** Python 3.14+ (Recommended).

1.  **Setup Environment**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

2.  **Compile GeoIP Database**
    VIBE-DNS uses a custom memory-mapped binary format for speed.
    ```bash
    # Compiles JSON or MaxMind MMDB into .vibe format
    python3 geoip_compiler.py --json ipinfo_lite.json --unified-output geoip.vibe
    ```

3.  **Run Server**
    ```bash
    # Validates config and starts the server
    python3 server.py --config config.yaml
    ```

---

## 📂 Configuration Guide

Configuration is handled in `config.yaml`. See `full_config.yaml` for a complete reference.

### Core Sections
* **`server`**: Bind IPs, ports, and ECS/MAC handling options.
* **`upstream`**: DNS-over-HTTPS/TLS providers, load balancing strategies, and circuit breaker thresholds.
* **`groups`**: Define clients by IP, Subnet, MAC, or GeoIP tag.
* **`policies`**: Combine Blocklists, Allowlists, and Upstream Groups.
* **`assignments`**: Map **Groups** → **Policies** (optionally triggered by **Schedules**).

### Example: Identifying a Client via ECS
```yaml
server:
  use_ecs: true

groups:
  remote_office:
    - "10.200.0.0/24"  # Matches if ECS option contains an IP in this range

assignments:
  remote_office:
    policy: "CorporatePolicy"
````

-----

## ⚠️ Disclaimer

This is a testing and educational project. While designed with performance and security principles (e.g., circuit breakers, resource limits), it is not a commercially supported enterprise product. Use at your own risk.


