import os
import sys
import signal
import argparse
import threading
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import load_config, reload_config, get_config
from src.sftp.server import SFTPServerThread, start_sftp_server
from src.api.app import app
from src.logger import api_log, sftp_log
from src.redis_client import get_redis


class Application:
    def __init__(self):
        self.sftp_server = None
        self.api_server = None
        self.running = False
        self._lock = threading.Lock()

    def start(self, config_file: str = "./config.yaml"):
        load_config(config_file)
        cfg = get_config()
        
        validation_errors = cfg.validate()
        if validation_errors:
            print("Configuration validation failed:", file=sys.stderr)
            for error in validation_errors:
                print(f"  - {error}", file=sys.stderr)
            sys.exit(1)

        print("[Redis] Connecting...")
        get_redis()

        sftp_log("APP_START", "SFTP Proxy starting...")
        api_log("APP_START", "SFTP Proxy API starting...")

        self.sftp_server = start_sftp_server()
        sftp_log("SFTP_STARTED", f"Listening on {cfg.server.get('host')}:{cfg.server.get('sftp_port')}")

        import uvicorn
        import asyncio

        def run_api():
            asyncio.set_event_loop(asyncio.new_event_loop())
            uvicorn.run(
                app,
                host=cfg.server.get('host', '0.0.0.0'),
                port=cfg.server.get('api_port', 8080),
                log_level="info"
            )

        self.api_server = threading.Thread(target=run_api, daemon=True)
        self.api_server.start()
        api_log("API_STARTED", f"Listening on {cfg.server.get('host')}:{cfg.server.get('api_port')}")

        self.running = True

        self._setup_signal_handlers()

        try:
            while self.running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        with self._lock:
            if not self.running:
                return
            self.running = False

        sftp_log("APP_STOP", "SFTP Proxy stopping...")
        api_log("APP_STOP", "SFTP Proxy API stopping...")

        if self.sftp_server:
            self.sftp_server.stop()

        sftp_log("APP_STOPPED", "SFTP Proxy stopped")
        api_log("APP_STOPPED", "SFTP Proxy API stopped")

    def reload(self):
        reload_config()
        sftp_log("APP_RELOAD", "Configuration reloaded")
        api_log("APP_RELOAD", "API Configuration reloaded")

    def _setup_signal_handlers(self):
        def signal_handler(signum, frame):
            if signum == signal.SIGINT:
                sftp_log("SIGNAL", "Received SIGINT, stopping...")
                self.stop()
            elif signum == signal.SIGTERM:
                sftp_log("SIGNAL", "Received SIGTERM, stopping...")
                self.stop()
            elif hasattr(signal, 'SIGHUP') and signum == signal.SIGHUP:
                sftp_log("SIGNAL", "Received SIGHUP, reloading config...")
                self.reload()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, signal_handler)


def main():
    parser = argparse.ArgumentParser(description="SFTP Proxy Server")
    parser.add_argument("-c", "--config", default="./config.yaml", help="Configuration file path")
    parser.add_argument("-r", "--reload", action="store_true", help="Reload configuration and exit")
    parser.add_argument("-t", "--test", action="store_true", help="Test configuration and exit")

    args = parser.parse_args()

    if args.reload:
        reload_config()
        print("Configuration reloaded")
        return

    if args.test:
        load_config(args.config)
        cfg = get_config()
        print(f"Configuration loaded successfully from {args.config}")
        print(f"Auth type: {cfg.auth.get('type')}")
        print(f"Storage type: {cfg.storage.get('type')}")
        
        auth_type = cfg.auth.get('type')
        redis_required = auth_type == 'token' or (auth_type == 'jwt' and cfg.auth.get('jwt', {}).get('redis_enabled', False))
        
        if redis_required:
            print("\nTesting Redis connection...")
            redis_client = get_redis()
            if redis_client.ping():
                print("[Redis] Connection test: OK")
            else:
                print("[Redis] Connection test: FAILED")
                sys.exit(1)
        else:
            print("\n[Redis] Skipped (not required for current auth type)")
        return

    app = Application()
    app.start(args.config)


if __name__ == "__main__":
    main()
