import subprocess, time, os, sys, select

python = "/home/ronzoro/safenestt-platform/apps/api/.venv/bin/python3"

# Check python
r = subprocess.run([python, "--version"], capture_output=True, text=True)
print(f"Python: {r.stdout.strip()}", flush=True)

env = os.environ.copy()
env.update({
    "MODE": "production",
    "HOST": "127.0.0.1",
    "PORT": "8002",
    "WORKERS": "1",
    "DB_HOST": "127.0.0.1",
    "DB_PORT": "54322",
    "DB_NAME": "safenestt_ai",
    "DB_SSL_MODE": "disable",
    "SAFENESTT_DB_PASSWORD": "postgres",
    "SAFENESTT_ENCRYPTION_KEY": "snZ-LRhUeiwflTvuIArgeb-AOhukQOhZcYGSOjD44eM=",
    "OPENROUTER_API_KEY": "",
    "MODEL_PROVIDER": "ollama",
    "MODEL_BASE_URL": "http://localhost:11434/v1",
    "MODEL_NAME": "qwen3:1.7b",
    "API_KEY_PEPPER": "safenestt-pepper-change-in-production",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
})

print("Starting uvicorn on 127.0.0.1:8002...", flush=True)
proc = subprocess.Popen(
    [python, "-m", "uvicorn", "safenestt.api:app",
     "--host", "127.0.0.1", "--port", "8002", "--workers", "1",
     "--log-level", "info", "--proxy-headers"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    env=env,
    cwd="/home/ronzoro/safenestt-ai",
    text=True,
)

# Wait for startup or failure
start = time.time()
while time.time() - start < 10:
    line = proc.stdout.readline()
    if line:
        print(line, end="", flush=True)
    if proc.poll() is not None:
        break
    # Check if server is listening
    try:
        import urllib.request
        r = urllib.request.urlopen("http://127.0.0.1:8002/v1/health", timeout=2)
        print(f"\nServer is UP! Status: {r.status}", flush=True)
        print(f"Response: {r.read().decode()}", flush=True)
        print(f"\n=== ENGINE STARTED SUCCESSFULLY ===", flush=True)
        print(f"PID: {proc.pid}", flush=True)
        sys.exit(0)
    except Exception as e:
        pass
    time.sleep(0.5)

if proc.poll() is not None:
    print(f"\n=== Process exited with code {proc.returncode} ===", flush=True)
    sys.exit(proc.returncode)

print("\n=== Timeout waiting for server ===", flush=True)
proc.terminate()
sys.exit(1)
