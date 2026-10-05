"""Server launcher for the TraceVault web service.

Starts the FastAPI app (api.py). This file knows nothing about the database or ledger: the browser UI and
every other client talk to the REST API only.

Run:
    python -m tracevault.server [--host 127.0.0.1] [--port 8000] [--data-dir ./data]

Secrets and the first administrator come from the environment / .env (see .env.example).
"""
import argparse, os, sys
import uvicorn
from .api import create_app
from .config import ConfigError, load_env

def main():
    parser = argparse.ArgumentParser(description="TraceVault Secure Distribution Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    parser.add_argument("--data-dir", default=os.path.join(os.getcwd(), "data"), help="Directory for database, ledger and evidence")
    args = parser.parse_args()

    load_env()
    try:
        app = create_app(data_dir=args.data_dir)
    except ConfigError as e:
        sys.exit(f"Configuration error: {e}")

    print("\n" + "=" * 65)
    print("  TRACEVAULT POST-QUANTUM SECURE DISTRIBUTION & LEDGER")
    print("=" * 65)
    print(f"  Web interface & API: http://{args.host}:{args.port}")
    print(f"  Data directory:      {os.path.abspath(args.data_dir)}")
    if not os.environ.get("TV_ADMIN_PASSWORD"):
        print("  Note: TV_ADMIN_PASSWORD is not set; sign in with an existing administrator.")
    print("=" * 65 + "\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

if __name__ == "__main__":
    main()
