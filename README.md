# Real-Time Threat Intelligence Cache & Detection System

A high-performance cybersecurity threat intelligence engine built with **FastAPI**, **PostgreSQL**, **Redis**, and a modern **React / Vite** dashboard.

---

## ⚡ Quick Start (One Command)

### Prerequisites
Make sure you have the following installed on your machine:
- **Python 3.12+**
- **Node.js 18+ & npm**
- **Docker Desktop** (must be running)

### Running the Project
Clone the repository and run `start.py`:

```bash
git clone https://github.com/debayan91/basic_redis_project.git
cd basic_redis_project
python3 start.py
```

`start.py` will automatically:
1. Provision configuration files (`.env`).
2. Create a Python virtual environment (`.venv`) and install all dependencies.
3. Start PostgreSQL and Redis infrastructure containers via Docker Compose.
4. Run Alembic database migrations and seed initial threat indicator datasets.
5. Install frontend npm dependencies if missing.
6. Launch the **FastAPI backend** (`http://localhost:8000`) and the **React UI** (`http://localhost:5173`).

---

## 🌐 Application URLs

- **Web Dashboard:** [http://localhost:5173](http://localhost:5173)
- **FastAPI API Server:** [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check Endpoint:** [http://localhost:8000/health](http://localhost:8000/health)

---

## 🛠 Manual Alternative (Docker Compose)

If you prefer to run the entire system directly in Docker containers:

```bash
docker compose up -d --build
docker compose exec backend alembic upgrade head
docker compose exec backend python -m app.db.seed
```

---

## 🧪 Testing

To run the backend test suite:

```bash
source .venv/bin/activate
pytest backend/tests -v
```
