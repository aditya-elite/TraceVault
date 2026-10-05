"""Generate (or migrate) the secrets TraceVault needs and print them as .env lines.

    python -m tracevault.keygen                 # brand-new secrets
    python -m tracevault.keygen --migrate data  # convert the OLD flat files (master.key, api_secret.key,
                                                # ledger/node-N/node_key.json) so existing data keeps working

Output goes to stdout only; redirect it yourself (`> .env`) and keep that file out of version control.
"""
import argparse, json, os, secrets, sys
from . import crypto as C
from .ledger import N_NODES, node_key_env

def fresh() -> dict:
    out = {"TV_MASTER_KEY": C.b64e(os.urandom(32)), "TV_JWT_SECRET": secrets.token_urlsafe(48)}
    for i in range(N_NODES):
        out[node_key_env(f"node-{i+1}")] = C.keypair_to_env(*C.dsa_keygen())
    return out

def migrate(data_dir: str) -> dict:
    out, rd = {}, lambda *p: open(os.path.join(data_dir, *p), "rb").read()
    out["TV_MASTER_KEY"] = C.b64e(rd("master.key"))
    p = os.path.join(data_dir, "api_secret.key")
    out["TV_JWT_SECRET"] = C.b64e(rd("api_secret.key")) if os.path.exists(p) else secrets.token_urlsafe(48)
    for i in range(N_NODES):
        nid = f"node-{i+1}"
        k = json.loads(rd("ledger", nid, "node_key.json"))
        out[node_key_env(nid)] = k["pk"] + ":" + k["sk"]
    return out

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--migrate", metavar="DATA_DIR", help="read legacy flat-file secrets from this directory")
    a = ap.parse_args()
    vals = migrate(a.migrate) if a.migrate else fresh()
    for k, v in vals.items():
        print(f"{k}={v}")
    if a.migrate:
        print("# Migrated. After confirming the app starts, securely delete master.key, api_secret.key and "
              "ledger/node-*/node_key.json.", file=sys.stderr)

if __name__ == "__main__":
    main()
