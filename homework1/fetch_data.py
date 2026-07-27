#!/usr/bin/env python3
"""Fetch Bitcoin testnet transaction and block data from blockstream.info API"""
import requests
import json
import sys

print("="*60)
print("  Fetching Bitcoin Testnet Data")
print("="*60)

# 1. Get latest block hash
print("\n[1] Fetching latest testnet block hash...")
tip_hash = requests.get("https://blockstream.info/testnet/api/blocks/tip/hash", timeout=15).text.strip()
print(f"    Latest block: {tip_hash}")

# 2. Get block info
print("\n[2] Fetching block info...")
block_info = requests.get(f"https://blockstream.info/testnet/api/block/{tip_hash}", timeout=15).json()
with open("block_info.json", "w", encoding="utf-8") as f:
    json.dump(block_info, f, indent=2, ensure_ascii=False)
print(f"    Height: {block_info.get('height')}")
print(f"    Transactions: {block_info.get('tx_count')}")
print(f"    Size: {block_info.get('size')} bytes")
print(f"    Timestamp: {block_info.get('timestamp')}")

# 3. Get block raw binary data -> hex
print("\n[3] Fetching block raw data...")
resp = requests.get(f"https://blockstream.info/testnet/api/block/{tip_hash}/raw", timeout=30)
block_hex = resp.content.hex()
with open("block_raw_hex.txt", "w") as f:
    f.write(block_hex)
print(f"    Block hex: {len(block_hex)} chars ({len(block_hex)//2} bytes)")

# 4. Get transaction IDs
print("\n[4] Fetching transaction list...")
txs_resp = requests.get(f"https://blockstream.info/testnet/api/block/{tip_hash}/txids", timeout=15)
txids = txs_resp.json()
print(f"    Got {len(txids)} transaction IDs")

# 5. Get first transaction (coinbase)
print("\n[5] Fetching coinbase transaction...")
coinbase_txid = txids[0]
resp = requests.get(f"https://blockstream.info/testnet/api/tx/{coinbase_txid}/raw", timeout=15)
coinbase_hex = resp.content.hex()
with open("tx_raw_hex.txt", "w") as f:
    f.write(coinbase_hex)
print(f"    Coinbase TXID: {coinbase_txid}")
print(f"    Coinbase hex: {len(coinbase_hex)} chars ({len(coinbase_hex)//2} bytes)")

# Save coinbase tx info
tx_info = requests.get(f"https://blockstream.info/testnet/api/tx/{coinbase_txid}", timeout=15).json()
with open("tx_coinbase_info.json", "w", encoding="utf-8") as f:
    json.dump(tx_info, f, indent=2, ensure_ascii=False)

# 6. Find a normal transaction (non-coinbase)
print("\n[6] Finding normal (non-coinbase) transaction...")
normal_txid = None
for txid in txids[1:20]:
    try:
        txi = requests.get(f"https://blockstream.info/testnet/api/tx/{txid}", timeout=10).json()
        is_coinbase = any(vin.get("is_coinbase", False) for vin in txi.get("vin", []))
        if not is_coinbase:
            normal_txid = txid
            break
    except:
        continue

if normal_txid:
    resp = requests.get(f"https://blockstream.info/testnet/api/tx/{normal_txid}/raw", timeout=15)
    normal_hex = resp.content.hex()
    with open("tx_normal_raw_hex.txt", "w") as f:
        f.write(normal_hex)
    print(f"    Normal TXID: {normal_txid}")
    print(f"    Normal tx hex: {len(normal_hex)} chars ({len(normal_hex)//2} bytes)")

    normal_info = requests.get(f"https://blockstream.info/testnet/api/tx/{normal_txid}", timeout=15).json()
    with open("tx_normal_info.json", "w", encoding="utf-8") as f:
        json.dump(normal_info, f, indent=2, ensure_ascii=False)

    # Print tx summary
    print(f"\n    --- Normal Transaction Summary ---")
    print(f"    TXID: {normal_txid}")
    print(f"    Size: {normal_info.get('size')} bytes")
    print(f"    Inputs: {len(normal_info.get('vin', []))}")
    print(f"    Outputs: {len(normal_info.get('vout', []))}")
    for i, vout in enumerate(normal_info.get("vout", [])):
        print(f"      Output #{i}: {vout.get('value', 0):,} satoshis")
        addr = vout.get("scriptpubkey_address", "unknown")
        print(f"        Address: {addr}")
else:
    print("    WARNING: No normal transaction found in first 20 txs")

print(f"\n{'='*60}")
print("  Data fetch complete!")
print("  Files created:")
print("    block_info.json       - Block metadata")
print("    block_raw_hex.txt     - Block raw hex data")
print("    tx_raw_hex.txt        - Coinbase tx raw hex")
print("    tx_coinbase_info.json - Coinbase tx metadata")
print("    tx_normal_raw_hex.txt - Normal tx raw hex")
print("    tx_normal_info.json   - Normal tx metadata")
print(f"{'='*60}")
