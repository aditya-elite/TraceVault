"""Server launcher for TraceVault web service and API.

Starts the FastAPI server with persistent SQLite database, encrypted document vault,
4-node quorum ledger, and the interactive web interface.

Run:
    python -m tracevault.server [--port 8000] [--data-dir ./data]
"""
import argparse, os, sys
import uvicorn
from .api import create_app

def main():
    parser = argparse.ArgumentParser(description="TraceVault Secure Distribution Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    parser.add_argument("--data-dir", default=os.path.join(os.getcwd(), "data"), help="Directory for database and keys")
    args = parser.parse_args()

    # Pre-seed default demo users if creating a new data dir
    users = {
        "admin": {"password": "admin123", "role": "admin"},
        "alice": {"password": "alice123", "role": "recipient"},
        "bob": {"password": "bob123", "role": "recipient"},
        "charlie": {"password": "charlie123", "role": "recipient"},
        "investigator": {"password": "investigator123", "role": "investigator"}
    }
    
    app = create_app(data_dir=args.data_dir, users=users)
    print("\n" + "=" * 65)
    print("  TRACEVAULT POST-QUANTUM SECURE DISTRIBUTION & LEDGER")
    print("=" * 65)
    print(f"  Web Interface & API: http://{args.host}:{args.port}")
    print(f"  Data Directory:      {os.path.abspath(args.data_dir)}")
    print(f"  Default Users:       admin, alice, bob, charlie, investigator")
    print(f"  Default Passwords:   <username>123 (e.g. admin123, bob123)")
    print("=" * 65 + "\n")
    
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

if __name__ == "__main__":
    main()
