import subprocess, os, sys, time, signal, urllib.request

python = "/home/ronzoro/safenestt-platform/apps/api/.venv/bin/python3"

env = os.environ.copy()
env.update({
    "PYTHONPATH": "/home/ronzoro/safenestt-ai:" + os.environ.get("PYTHONPATH", ""),
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

# Start uvicorn as a background process that stays alive
proc = subprocess.Popen(
    [python, "-m", "uvicorn", "safenestt.api.app:app",
     "--host", "127.0.0.1", "--port", "8002", "--workers", "1",
     "--log-level", "info"],
    stdout=open("/tmp/safenestt-engine.log", "w"),
    stderr=subprocess.STDOUT,
    env=env,
    cwd="/home/ronzoro/safenestt-ai",
    start_new_session=True,  # Detach from parent
)

print(f"Started engine PID: {proc.pid}", flush=True)

# Wait for startup
start = time.time()
while time.time() - start < 15:
    time.sleep(0.5)
    # Check if process died
    if proc.poll() is not None:
        print(f"Process died with code {proc.returncode}", flush=True)
        sys.exit(1)
    # Check if port is listening
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        r = s.connect_ex(("127.0.0.1", 8002))
        s.close()
        if r == 0:
            print("Port 8002 is listening!", flush=True)
            break
    except:
        pass
else:
    print("Timeout waiting for port", flush=True)
    sys.exit(1)

# Read some log output
try:
    with open("/tmp/safenestt-engine.log") as f:
        lines = f.readlines()
    print("\n--- Last 5 log lines ---", flush=True)
    for l in lines[-5:]:
        print(l, end="", flush=True)
except:
    pass

print("\nEngine is running in background. PID:", proc.pid, flush=True)
