"""Standalone command-line verifier for TraceVault ledger exports.

Verifies:
1. Hash-chain continuity across all blocks from genesis.
2. Record hash integrity: SHA3(index || event || sig || signer || prev_hash).
3. Quorum certificates: at least 3 of 4 valid node ML-DSA-65 attestations per block.
4. Recipient event signatures against the provided public key registry.
5. Multi-node consensus: identical state held across >= 3 nodes.

Run:
    python -m tracevault.verify_ledger <ledger_export.json> <registry.json>
"""
import json, sys
from . import crypto as C
from .ledger import record_hash, GENESIS, QUORUM

def verify_export(export_data: dict, registry_data: dict) -> dict:
    node_pks = {nid: C.b64d(pk) for nid, pk in export_data["node_pks"].items()}
    recipients = registry_data.get("recipients", {})
    results = {"nodes": {}, "quorum_records": 0, "verified": False, "errors": []}
    
    node_heads = {}
    for nid, records in export_data.get("nodes", {}).items():
        prev = GENESIS
        node_errs = []
        for i, r in enumerate(records):
            if r["index"] != i:
                node_errs.append(f"Block #{i}: index discrepancy ({r['index']} != {i})")
            if r["prev_hash"] != prev:
                node_errs.append(f"Block #{i}: broken chain link")
            
            # Record hash check
            expected_hash = record_hash(i, r["event"], r["signature"], r["signer_key_id"], r["prev_hash"])
            if r["record_hash"] != expected_hash:
                node_errs.append(f"Block #{i}: record hash mismatch")
                
            # Quorum attestations check
            atts = r.get("attestations", {})
            valid_atts = 0
            for att_nid, sig_b64 in atts.items():
                if att_nid in node_pks:
                    pk = node_pks[att_nid]
                    if C.dsa_verify(pk, b"TV-ATTEST" + r["record_hash"].encode(), C.b64d(sig_b64)):
                        valid_atts += 1
            if valid_atts < QUORUM:
                node_errs.append(f"Block #{i}: only {valid_atts}/{QUORUM} valid node attestations")
                
            # Recipient signature check
            kid = r["signer_key_id"]
            if kid not in recipients:
                node_errs.append(f"Block #{i}: signer {kid} not in registry")
            else:
                signer_pk = C.b64d(recipients[kid]["dsa_pk"])
                if not C.dsa_verify(signer_pk, C.event_message(r["event"]), C.b64d(r["signature"])):
                    node_errs.append(f"Block #{i}: recipient signature invalid")
                    
            prev = r["record_hash"]
        
        node_heads[nid] = prev
        results["nodes"][nid] = {
            "record_count": len(records),
            "head_hash": prev,
            "valid": len(node_errs) == 0,
            "errors": node_errs
        }
    
    valid_nodes = [nid for nid, stat in results["nodes"].items() if stat["valid"]]
    heads = {node_heads[nid] for nid in valid_nodes}
    
    if len(valid_nodes) >= QUORUM and len(heads) == 1:
        results["verified"] = True
        results["quorum_records"] = results["nodes"][valid_nodes[0]]["record_count"]
    else:
        results["verified"] = False
        results["errors"].append(f"Consensus failed: {len(valid_nodes)}/4 valid nodes, distinct heads: {heads}")
        
    return results

def main():
    if len(sys.argv) < 3:
        print("Usage: python -m tracevault.verify_ledger <ledger_export.json> <registry.json>")
        sys.exit(1)
        
    with open(sys.argv[1], "r") as f:
        export_data = json.load(f)
    with open(sys.argv[2], "r") as f:
        reg_data = json.load(f)
        
    res = verify_export(export_data, reg_data)
    print("\n" + "=" * 60)
    print(f"TRACEVAULT INDEPENDENT LEDGER VERIFIER")
    print(f"Status: {'[VERIFIED - QUORUM VALID]' if res['verified'] else '[FAILED - INTEGRITY COMPROMISED]'}")
    print(f"Quorum Blocks: {res['quorum_records']}")
    print("=" * 60)
    for nid, stat in res["nodes"].items():
        status_txt = "VALID" if stat["valid"] else f"FAILED ({len(stat['errors'])} errors)"
        print(f"Node {nid}: {status_txt} | Records: {stat['record_count']} | Head: {stat['head_hash'][:16]}...")
        for err in stat["errors"]:
            print(f"   [!] {err}")
    if res["errors"]:
        for e in res["errors"]:
            print(f"[CRITICAL] {e}")
    sys.exit(0 if res["verified"] else 1)

if __name__ == "__main__":
    main()
