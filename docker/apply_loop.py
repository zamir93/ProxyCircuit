# ProxyCircuit Docker privileged worker watcher - Mohammad Zamir Akbari
"""Poll the service-owned deployment marker directory. No public API, no arbitrary commands."""
import os
from pathlib import Path
import subprocess
import sys
import time

QUEUE = Path('/var/lib/rpmgr/deploy')

def main() -> None:
    print('[ProxyCircuit] Docker deployment watcher running', flush=True)
    while True:
        if list(QUEUE.glob('pending-*.json')):
            completed = subprocess.run([sys.executable, '-m', 'app.worker'], check=False)
            if completed.returncode:
                print(f'[ProxyCircuit] Deployment failed: {completed.returncode}; check status.json', flush=True)
                # Avoid high-frequency retries if a pending marker cannot be removed.
                time.sleep(5)
        time.sleep(1)

if __name__ == '__main__':
    main()
