#!/usr/bin/env python3
"""
Launcher script for Threat Intelligence Detection & Caching System.
Starts Postgres and Redis (via Docker Compose), runs database migrations,
seeds initial threat indicators, and launches FastAPI backend and Vite frontend.
"""

import os
import sys
import time
import socket
import signal
import shutil
import subprocess
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
VENV_PYTHON = ROOT_DIR / ".venv" / "bin" / "python"
VENV_ALEMBIC = ROOT_DIR / ".venv" / "bin" / "alembic"

# Colors for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

running_processes: list[subprocess.Popen] = []


def log(msg: str, color: str = CYAN) -> None:
    print(f"{color}{BOLD}[SYSTEM]{RESET} {msg}", flush=True)


def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open and accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def wait_for_service(name: str, host: str, port: int, timeout_sec: int = 30) -> bool:
    """Poll until a network service is available or timeout occurs."""
    log(f"Waiting for {name} on {host}:{port}...", YELLOW)
    start_time = time.time()
    while time.time() - start_time < timeout_sec:
        if check_port(host, port):
            log(f"✓ {name} is ready on {host}:{port}", GREEN)
            return True
        time.sleep(1)
    log(f"✗ Timed out waiting for {name} on {host}:{port}", RED)
    return False


def ensure_docker_containers() -> None:
    """Ensure PostgreSQL and Redis containers are running."""
    docker_cmd = shutil.which("docker")
    if not docker_cmd:
        log("Docker executable not found! Please install Docker.", RED)
        sys.exit(1)

    log("Checking Docker containers for Postgres & Redis...", CYAN)
    try:
        res = subprocess.run(
            [docker_cmd, "compose", "ps", "--services", "--filter", "status=running"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=True,
        )
        running_services = set(res.stdout.strip().split())
    except Exception as e:
        log(f"Error checking docker services: {e}", YELLOW)
        running_services = set()

    needed = {"postgres", "redis"} - running_services
    if needed:
        log(f"Starting required infrastructure services: {', '.join(needed)}...", CYAN)
        subprocess.run(
            [docker_cmd, "compose", "up", "-d", "postgres", "redis"],
            cwd=ROOT_DIR,
            check=True,
        )
    else:
        log("✓ Infrastructure containers (postgres, redis) already running", GREEN)

    # Wait for postgres (host port 5434) and redis (host port 6380)
    if not wait_for_service("PostgreSQL", "localhost", 5434, 30):
        sys.exit(1)
    if not wait_for_service("Redis", "localhost", 6380, 20):
        sys.exit(1)


def run_database_migrations_and_seed(python_bin: Path, alembic_bin: Path) -> None:
    """Run Alembic database migrations and seed initial dataset."""
    log("Applying database migrations...", CYAN)
    try:
        subprocess.run(
            [str(alembic_bin), "upgrade", "head"],
            cwd=BACKEND_DIR,
            check=True,
        )
        log("✓ Database migrations up to date", GREEN)
    except subprocess.CalledProcessError as e:
        log(f"Migration error: {e}", RED)
        sys.exit(1)

    log("Seeding threat intelligence indicator data...", CYAN)
    try:
        subprocess.run(
            [str(python_bin), "-m", "app.db.seed"],
            cwd=BACKEND_DIR,
            check=True,
        )
        log("✓ Threat intelligence seeds loaded successfully", GREEN)
    except subprocess.CalledProcessError as e:
        log(f"Seed script encountered an issue (non-fatal if already seeded): {e}", YELLOW)


def check_node_dependencies() -> None:
    """Ensure frontend dependencies are installed."""
    node_modules = FRONTEND_DIR / "node_modules"
    npm_cmd = shutil.which("npm")
    if not npm_cmd:
        log("npm not found in PATH! Please ensure Node.js is installed.", RED)
        sys.exit(1)

    if not node_modules.exists():
        log("Frontend node_modules missing. Installing npm dependencies...", YELLOW)
        subprocess.run([npm_cmd, "install"], cwd=FRONTEND_DIR, check=True)
        log("✓ Frontend dependencies installed", GREEN)


def start_backend(python_bin: Path) -> subprocess.Popen:
    """Start FastAPI uvicorn backend."""
    if check_port("localhost", 8000):
        log("Backend port 8000 is already active.", YELLOW)
        return None

    log("Starting FastAPI backend server on http://localhost:8000...", CYAN)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR)

    proc = subprocess.Popen(
        [
            str(python_bin),
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--reload",
        ],
        cwd=BACKEND_DIR,
        env=env,
    )
    running_processes.append(proc)
    return proc


def start_frontend() -> subprocess.Popen:
    """Start Vite development frontend server."""
    if check_port("localhost", 5173):
        log("Frontend port 5173 is already active.", YELLOW)
        return None

    log("Starting React Frontend dev server on http://localhost:5173...", CYAN)
    npm_cmd = shutil.which("npm")
    proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=FRONTEND_DIR,
    )
    running_processes.append(proc)
    return proc


def shutdown(signum=None, frame=None) -> None:
    """Cleanly shut down spawned child processes on exit/Ctrl+C."""
    log("\nStopping application servers started by this script...", YELLOW)
    for p in running_processes:
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass

    for p in running_processes:
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()

    log("✓ All processes cleanly stopped.", GREEN)
    sys.exit(0)


def main() -> None:
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"\n{BOLD}{CYAN}======================================================{RESET}")
    print(f"{BOLD}{CYAN}   🚀 REAL-TIME THREAT INTELLIGENCE SYSTEM BOOTSTRAP  {RESET}")
    print(f"{BOLD}{CYAN}======================================================{RESET}\n")

    # Resolve python and alembic binaries
    python_bin = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)
    alembic_bin = VENV_ALEMBIC if VENV_ALEMBIC.exists() else Path(shutil.which("alembic") or "alembic")

    # 1. Docker infrastructure (PostgreSQL & Redis)
    ensure_docker_containers()

    # 2. Database migrations & seeds
    run_database_migrations_and_seed(python_bin, alembic_bin)

    # 3. Node frontend dependencies check
    check_node_dependencies()

    # 4. Launch backend
    start_backend(python_bin)
    if not wait_for_service("Backend API", "localhost", 8000, 15):
        log("Backend failed to respond on port 8000.", RED)
        shutdown()

    # 5. Launch frontend
    start_frontend()
    frontend_port = 5173 if check_port("localhost", 5173) else 5174
    if not wait_for_service("Frontend UI", "localhost", frontend_port, 15):
        log("Frontend failed to respond.", RED)
        shutdown()

    print(f"\n{BOLD}{GREEN}======================================================{RESET}")
    print(f"{BOLD}{GREEN}   ✓ SYSTEM FULLY OPERATIONAL AND READY!{RESET}")
    print(f"{BOLD}{GREEN}======================================================{RESET}")
    print(f"  • {BOLD}Web UI:{RESET}       http://localhost:{frontend_port}")
    print(f"  • {BOLD}API Server:{RESET}   http://localhost:8000")
    print(f"  • {BOLD}API Docs:{RESET}     http://localhost:8000/docs")
    print(f"  • {BOLD}Health Check:{RESET} http://localhost:8000/health")
    print(f"\nPress {BOLD}Ctrl+C{RESET} to stop services started by this script.\n")

    try:
        while True:
            time.sleep(1)
            for p in running_processes:
                if p.poll() is not None:
                    log(f"Process {p.args} stopped (exit code {p.returncode})", YELLOW)
                    shutdown()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
