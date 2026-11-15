import subprocess, sys, os, time, select

os.chdir("/home/ronzoro/safenestt-ai")

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

proc = subprocess.Popen(
    ["/home/ronzoro/safenestt-platform/apps/api/.venv/bin/python3", "-m", "uvicorn", "safenestt.api:app",
     "--host", "127.0.0.1", "--port", "8002", "--workers", "1",
     "--log-level", "debug", "--proxy-headers"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    env=env,
    cwd="/home/ronzoro/safenestt-ai",
)

# Read output for 5 seconds
import select
start = time.time()
lines = []
while time.time() - start < 5:
    ready, _, _ = select.select([proc.stdout], [], [], 0.5)
    if ready:
        line = proc.stdout.readline().decode("utf-8", errors="replace")
        if line:
            lines.append(line.strip())
            print(line.strip())
    if proc.poll() is not None:
        break

print(f"\n=== Process exited with code {proc.returncode} after {len(lines)} lines ===")
if proc.returncode != 0:
    print("LAST 10 LINES:")
    for l in lines[-10:]:
        print(" ", l)
