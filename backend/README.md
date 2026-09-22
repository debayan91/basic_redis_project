# Real-Time Threat Intelligence Cache & Detection System

A high-performance cybersecurity threat intelligence engine built with **FastAPI**, **PostgreSQL**, **Redis**, and **SQLAlchemy 2.x async**.

---

## 🏗 System Architecture

```
                                  +-----------------------+
                                  |  HTTP / WS Client     |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |     FastAPI App       |
                                  +-----------+-----------+
                                              |
                   +--------------------------+--------------------------+
                   |                          |                          |
                   v                          v                          v
       +-----------------------+  +-----------------------+  +-----------------------+
       |   Redis Blacklists    |  |  Redis Threat Cache   |  | Redis Counters / ZSET |
       |  blacklist:ip/domain  |  |  ti:ip / ti:domain    |  |   rank:threats        |
       +-----------------------+  +-----------+-----------+  +-----------------------+
                                              | (Cache Miss / Stale)
                                              v
                                  +-----------------------+
                                  | CTI Provider Factory  |
                                  | (Local / External/VT) |
                                  +-----------+-----------+
                                              |
                         +--------------------+--------------------+
                         |                                         |
                         v                                         v
             +-----------------------+                 +-----------------------+
             | PostgreSQL Database   |                 | External CTI Provider |
             | (CTI & Trusted Roots) |                 | (VirusTotal v3 / Mock)|
             +-----------------------+                 +-----------------------+
```

---

## 🚀 Key Features

1. **Indicator Normalization & Boundary Safety**:
   - Validates IPv4, IPv6, Domains, and URLs.
   - Strict hierarchical domain boundary checks prevents naive substring spoofing (e.g. `google.com.evil.com` is safely recognized as untrusted).
2. **Cache-First Lookup Pipeline**:
   - Redis Hashes (`ti:ip:<ip>`, `ti:domain:<domain>`, `ti:url:<sha256>`).
   - Configurable dynamic TTLs based on indicator risk level.
3. **External CTI Provider Abstraction**:
   - Pluggable `ThreatIntelligenceProvider` architecture supporting `LocalCTIProvider`, `VirusTotalProvider`, `MockExternalCTIProvider`, and `CompositeCTIProvider`.
   - Provider selection via `CTI_PROVIDER` (`local`, `virustotal`, `mock`, `composite`).
4. **Redis-Native Security Primitives**:
   - **Blacklist Sets**: `blacklist:ip`, `blacklist:domain`, `blacklist:url` for O(1) blocking.
   - **Atomic Counters**: `metric:lookups:total`, `metric:cache:hits`, `metric:cache:misses`, etc.
   - **Threat Ranking**: `rank:threats` Sorted Set for Top-N malicious indicators.
5. **Real-Time Alerts & WebSockets**:
   - Redis Pub/Sub channel `malicious_indicator_detected`.
   - Real-time WebSocket endpoint at `/api/ws/alerts`.
6. **Failure Resilience & Graceful Degradation**:
   - Handles upstream provider timeouts (504), rate limits (429), and service outages (503).
   - Redis and DB connection failures fall back gracefully without crashing.
   - Cached fallback served when providers are temporarily unreachable.
7. **Standalone Benchmarking Suite**:
   - Reproducible comparison of Mode A (Direct Provider) vs Mode B (Redis Cache-First) with JSON/CSV export.

---

## 🛠 Quick Start (Docker Compose)

```bash
# Clone repository and navigate to root
cd client_project

# Spin up all backend services (FastAPI + PostgreSQL + Redis)
docker compose up -d --build

# Run migrations and seed data
docker compose exec backend alembic upgrade head
docker compose exec backend python -m app.db.seed
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/check` | Look up threat verdict for an IP, domain, or URL |
| `GET` | `/api/stats` | Retrieve operational metrics, hit rates, and latency percentiles |
| `GET` | `/api/blacklist` | List all blacklisted indicators (supports filtering & pagination) |
| `POST` | `/api/blacklist` | Add an indicator directly to the Redis blacklist |
| `DELETE` | `/api/blacklist/{indicator}` | Remove an indicator from the Redis blacklist |
| `POST` | `/api/refresh/{indicator}` | Force bypass cache and refresh indicator from CTI provider |
| `GET` | `/health` | Application, PostgreSQL, and Redis connectivity health check |
| `WS` | `/api/ws/alerts` | WebSocket streaming real-time threat alert events |

---

## 🧪 Testing & Benchmarking

```bash
# Run complete test suite (191 tests)
pytest backend/tests -v

# Run reproducible benchmarking
python backend/scripts/benchmark.py --requests 100 --unique 20 --repetition 0.75 --format json
```
