#!/usr/bin/env python3
"""Send testnet transaction using real UTXO"""
from bitcoinlib.keys import Key
from bitcoinlib.networks import Network
from bitcoinlib.transactions import Transaction
import requests, json

WIF = 'cNEXw1tLGrsZFmD5SWPjfCgDECPvMHdsrAWi3b7xgdp5JBhgxSAu'
FROM = 'mzcQbD1arHqyBy66wQxQqERRYAdFkhQN3c'
TO = 'mvhYS76rbgg9pAnxxM2NbXjz19PGBydyQv'

print("=" * 55)
print("  SEND TESTNET TX")
print("=" * 55)
print("From:", FROM)
print("To:  ", TO)

# Get UTXO
r = requests.get(f'https://blockstream.info/testnet/api/address/{FROM}/utxo', timeout=15)
utxos = r.json()
if not utxos:
    print("No UTXOs found!")
    exit(1)
utxo = utxos[0]
total = utxo['value']
print(f"\nUTXO: {total} sat")

# Build
fee = 300
amt = total - fee
print(f"Fee: {fee}, Send: {amt} sat")

net = Network('testnet')
key = Key(import_key=WIF, network=net)
tx = Transaction(network=net, witness_type="legacy")
tx.add_input(utxo['txid'], utxo['vout'], keys=[key], value=total, address=FROM)
tx.add_output(amt, TO)
tx.sign()
raw = tx.raw_hex()
tid = tx.txid

print(f"Signed! TXID: {tid}")
print(f"Size: {len(raw)} chars = {len(raw)//2} bytes")

# Save
with open('my_tx_raw_hex.txt', 'w') as f:
    f.write(raw)
json.dump({'from': FROM, 'to': TO, 'txid': tid, 'hex_file': 'my_tx_raw_hex.txt'},
          open('tx_result.json', 'w'), indent=2)

# Broadcast
print("Broadcasting to blockstream...")
r = requests.post('https://blockstream.info/testnet/api/tx',
                   data=raw, headers={'Content-Type': 'text/plain'}, timeout=30)
print(f"Status: {r.status_code}")
if r.status_code == 200:
    txid = r.text.strip()
    print(f"SUCCESS! TXID: {txid}")
    print(f"https://blockstream.info/testnet/tx/{txid}")
else:
    print(f"Error: {r.text[:300]}")
    print("Trying mempool.space...")
    r2 = requests.post('https://mempool.space/testnet/api/tx',
                        data=raw, headers={'Content-Type': 'text/plain'}, timeout=30)
    print(f"Status: {r2.status_code}")
    if r2.status_code == 200:
        print(f"SUCCESS via mempool! TXID: {r2.text.strip()}")
    else:
        print(f"Error: {r2.text[:300]}")

def demo_tx_construction():
    """Demonstrate transaction construction manually"""
    print("\n" + "-"*60)
    print("  MANUAL TRANSACTION CONSTRUCTION DEMO")
    print("-"*60)
    print("""
A Bitcoin transaction consists of:
  [Version] [Input Count] [Inputs...] [Output Count] [Outputs...] [Locktime]

Each Input:
  [Prev TX Hash (32B)] [Prev Output Index (4B)] [ScriptSig Len (VarInt)] [ScriptSig] [Sequence (4B)]

Each Output:
  [Value in satoshis (8B)] [ScriptPubKey Len (VarInt)] [ScriptPubKey]

Example: P2PKH ScriptPubKey (25 bytes):
  76 a9 14 <20-byte-pubkey-hash> 88 ac
  OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG

Example: P2WPKH ScriptPubKey (22 bytes):
  00 14 <20-byte-witness-program>
  OP_0 <witness-program>

VarInt encoding:
  < 0xFD        : 1 byte
  <= 0xFFFF     : 0xFD + 2 bytes (LE)
  <= 0xFFFFFFFF : 0xFE + 4 bytes (LE)
  >  0xFFFFFFFF : 0xFF + 8 bytes (LE)
""")

    # Show example raw transaction construction
    print("\n  Example: Building a simple transaction manually:")
    print("""
  Version:         02000000          (version 2, little-endian)
  SegWit Marker:   00                (SegWit marker)
  SegWit Flag:     01                (SegWit flag)
  Input Count:     01                (1 input)
  Input:
    Prev TX:       <32 bytes>        (previous transaction hash, reversed)
    Prev Index:    00000000          (first output)
    ScriptSig Len: 00                (empty for SegWit)
    Sequence:      ffffffff          (final transaction)
  Output Count:    02                (2 outputs)
  Output 1:
    Value:         60ce580000000000   (5,820,000 satoshis, LE)
    ScriptPK Len:  16                (22 bytes)
    ScriptPK:      0014<20 bytes>    (P2WPKH)
  Output 2:
    Value:         d870110000000000   (1,143,000 satoshis, LE)
    ScriptPK Len:  16                (22 bytes)
    ScriptPK:      0014<20 bytes>    (P2WPKH)
  Locktime:        00000000          (immediate)

  Witness Data (for each input):
    Stack Items:   02
    Item 1 (sig):  <71-73 bytes signature>
    Item 2 (pk):   <33 bytes public key>
""")

    print("\n  [*] See btc_parser_main.py for complete parsing of real transactions")
    print("  [*] Run: python btc_parser_main.py demo")

if __name__ == "__main__":
    build_and_send()
