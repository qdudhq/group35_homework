#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bitcoin Transaction & Block Bit-Level Parser for Testnet"""
import struct, sys, datetime

def hex_to_bytes(h):
    return bytes.fromhex(h)

def read_varint(data, offset):
    first = data[offset]
    if first < 0xfd: return first, offset + 1
    elif first == 0xfd: return struct.unpack("<H", data[offset+1:offset+3])[0], offset + 3
    elif first == 0xfe: return struct.unpack("<I", data[offset+1:offset+5])[0], offset + 5
    elif first == 0xff: return struct.unpack("<Q", data[offset+1:offset+9])[0], offset + 9
    return 0, offset

def print_field(label, data, start, length, desc, extra=""):
    print(f"\n{'='*90}")
    print(f"[FIELD] {label} | Offset: [{start} - {start+length-1}] | {length} bytes")
    print(f"{'='*90}")
    print(f"{'Offset':<8} {'Hex':<6} {'Binary (8 bits per byte)':<80} {'Dec':<10} {'Description'}")
    print(f"{'-'*8} {'-'*6} {'-'*80} {'-'*10} {'-'*40}")
    for i in range(length):
        off = start + i
        bv = data[off]
        hex_str = f"0x{bv:02x}"
        print(f"{off:<8} {hex_str:<6} {bv:08b}    {bv:<10} {desc}")
    hf = data[start:start+length].hex()
    if length <= 8:
        vl = int.from_bytes(data[start:start+length], "little")
        vb = int.from_bytes(data[start:start+length], "big")
        print(f"\n  [*] Hex: 0x{hf}")
        print(f"  [*] LE value: {vl} (0x{vl:x})")
        print(f"  [*] BE value: {vb} (0x{vb:x})")
    else:
        print(f"\n  [*] Hex first 80: 0x{hf[:80]}...")
    if extra: print(f"  [*] {extra}")
    return start + length

def parse_script(sbytes, indent="  "):
    OP = {0x00:"OP_0",0x51:"OP_1",0x52:"OP_2",0x53:"OP_3",0x54:"OP_4",0x55:"OP_5",
          0x56:"OP_6",0x57:"OP_7",0x58:"OP_8",0x59:"OP_9",0x5a:"OP_10",
          0x5b:"OP_11",0x5c:"OP_12",0x5d:"OP_13",0x5e:"OP_14",0x5f:"OP_15",0x60:"OP_16",
          0x61:"OP_NOP",0x63:"OP_IF",0x64:"OP_NOTIF",0x67:"OP_ELSE",0x68:"OP_ENDIF",
          0x69:"OP_VERIFY",0x6a:"OP_RETURN",0x76:"OP_DUP",0x87:"OP_EQUAL",
          0x88:"OP_EQUALVERIFY",0xa8:"OP_SHA256",0xa9:"OP_HASH160",0xac:"OP_CHECKSIG",
          0xad:"OP_CHECKSIGVERIFY",0xae:"OP_CHECKMULTISIG",0xaf:"OP_CHECKMULTISIGVERIFY"}
    parts = []
    i = 0
    while i < len(sbytes):
        op = sbytes[i]
        if op == 0x00: parts.append(f"{indent}{i:02x}: OP_0"); i+=1
        elif 0x01<=op<=0x4b:
            d=sbytes[i+1:i+1+op]; parts.append(f"{indent}{i:02x}: PUSH {op}B -> 0x{d.hex()}"); i+=1+op
        elif op==0x4c:
            dl=sbytes[i+1]; parts.append(f"{indent}{i:02x}: PUSHDATA1 {dl}B"); i+=2+dl
        elif op==0x4d:
            dl=struct.unpack("<H",sbytes[i+1:i+3])[0]; parts.append(f"{indent}{i:02x}: PUSHDATA2 {dl}B"); i+=3+dl
        elif op==0x4e:
            dl=struct.unpack("<I",sbytes[i+1:i+5])[0]; parts.append(f"{indent}{i:02x}: PUSHDATA4 {dl}B"); i+=5+dl
        elif op in OP: parts.append(f"{indent}{i:02x}: {OP[op]} (0x{op:02x})"); i+=1
        else: parts.append(f"{indent}{i:02x}: ??? (0x{op:02x})"); i+=1
    return "\n".join(parts)

def parse_transaction(tx_hex):
    """Parse Bitcoin transaction byte-by-byte with bit-level detail"""
    tx = hex_to_bytes(tx_hex)
    total = len(tx)
    off = 0
    print("\n" + "="*90)
    print("  BITCOIN TRANSACTION - BYTE-LEVEL PARSING  ")
    print("="*90)
    print(f"Total: {total} bytes ({total*2} hex chars)")

    off = print_field("[1] VERSION", tx, off, 4, "Transaction version (LE)",
                       f"Version = {int.from_bytes(tx[0:4], 'little')}")

    is_sw = False
    if off < total and tx[off] == 0x00 and off+1 < total and tx[off+1] == 0x01:
        is_sw = True
        print(f"\n[SEGWIT] Marker=0x00, Flag=0x01 at offset {off}-{off+1}")
        print(f"  {off}: 0x00 | 00000000 | SegWit marker")
        print(f"  {off+1}: 0x01 | 00000001 | SegWit flag")
        off += 2

    in_cnt, noff = read_varint(tx, off)
    vlen = noff - off
    print(f"\n[FIELD] [2] INPUT COUNT = {in_cnt} (VarInt, {vlen}B)")
    for i in range(vlen):
        print(f"  {off+i}: 0x{tx[off+i]:02x} | {tx[off+i]:08b} | {tx[off+i]}")
    off = noff

    for idx in range(in_cnt):
        print(f"\n{'#'*90}\n### INPUT #{idx+1} ###\n{'#'*90}")
        prev = tx[off:off+32]
        real_txid = prev[::-1].hex()
        off = print_field("[3a] PREV TX HASH", tx, off, 32, "Prev tx hash (internal reversed)",
                           f"Real TXID: {real_txid}")
        off = print_field("[3b] PREV OUTPUT INDEX", tx, off, 4, "Output index (LE)",
                           f"Index = {int.from_bytes(tx[off-4:off], 'little')}")
        slen, s_off = read_varint(tx, off)
        s_vlen = s_off - off
        print(f"\n[FIELD] [3c] SCRIPTSIG LENGTH = {slen}B (VarInt)")
        for j in range(s_vlen):
            print(f"  {off+j}: 0x{tx[off+j]:02x} | {tx[off+j]:08b} | {tx[off+j]}")
        off = s_off
        if slen > 0:
            print(f"\n{'='*90}")
            print(f"[FIELD] [3d] SCRIPTSIG | Offset: [{off} - {off+slen-1}] | {slen}B")
            print(f"{'='*90}")
            print(f"{'Offset':<8} {'Hex':<6} {'Binary (8 bits)':<80} {'Dec':<10} {'Opcode'}")
            print(f"{'-'*8} {'-'*6} {'-'*80} {'-'*10} {'-'*20}")
            for j in range(slen):
                bv = tx[off+j]
                opdesc = ""
                if bv == 0x00: opdesc = "OP_0"
                elif 0x01 <= bv <= 0x4b: opdesc = f"PUSH_DATA({bv})"
                elif bv == 0x4c: opdesc = "OP_PUSHDATA1"
                elif bv == 0x4d: opdesc = "OP_PUSHDATA2"
                elif bv == 0x4e: opdesc = "OP_PUSHDATA4"
                elif 0x50 <= bv <= 0x60: opdesc = f"OP_{bv-0x50}"
                elif bv == 0x61: opdesc = "OP_NOP"
                elif bv == 0x76: opdesc = "OP_DUP"
                elif bv == 0xa9: opdesc = "OP_HASH160"
                elif bv == 0xac: opdesc = "OP_CHECKSIG"
                elif bv == 0x88: opdesc = "OP_EQUALVERIFY"
                print(f"{off+j:<8} 0x{bv:02x}  {bv:08b}    {bv:<10} {opdesc}")
            print("\n  [*] Script parse:")
            print(parse_script(tx[off:off+slen]))
            off += slen
        else:
            print("  [*] ScriptSig empty (Coinbase)")

        off = print_field("[3e] SEQUENCE", tx, off, 4, "Sequence (LE)",
                           f"Sequence = 0x{tx[off-4:off].hex()}")

    out_cnt, noff = read_varint(tx, off)
    vlen = noff - off
    print(f"\n[FIELD] [4] OUTPUT COUNT = {out_cnt} (VarInt, {vlen}B)")
    for i in range(vlen):
        print(f"  {off+i}: 0x{tx[off+i]:02x} | {tx[off+i]:08b} | {tx[off+i]}")
    off = noff

    for idx in range(out_cnt):
        print(f"\n{'#'*90}\n### OUTPUT #{idx+1} ###\n{'#'*90}")
        vs = off
        val_sat = int.from_bytes(tx[vs:vs+8], "little")
        off = print_field("[5a] VALUE (satoshis)", tx, off, 8, "Value in satoshis (LE)",
                           f"Amount = {val_sat:,} sat = {val_sat/1e8:.8f} BTC")
        pklen, p_off = read_varint(tx, off)
        pk_vlen = p_off - off
        print(f"\n[FIELD] [5b] SCRIPTPUBKEY LENGTH = {pklen}B (VarInt)")
        for j in range(pk_vlen):
            print(f"  {off+j}: 0x{tx[off+j]:02x} | {tx[off+j]:08b} | {tx[off+j]}")
        off = p_off
        if pklen > 0:
            print(f"\n{'='*90}")
            print(f"[FIELD] [5c] SCRIPTPUBKEY | Offset: [{off} - {off+pklen-1}] | {pklen}B")
            print(f"{'='*90}")
            print(f"{'Offset':<8} {'Hex':<6} {'Binary (8 bits)':<80} {'Dec':<10}")
            print(f"{'-'*8} {'-'*6} {'-'*80} {'-'*10}")
            for j in range(pklen):
                bv = tx[off+j]
                print(f"{off+j:<8} 0x{bv:02x}  {bv:08b}    {bv:<10}")
            print("\n  [*] Script parse:")
            print(parse_script(tx[off:off+pklen]))
            shex = tx[off:off+pklen].hex()
            if shex.startswith("76a914") and shex.endswith("88ac"):
                print(f"\n  [*] Script Type: P2PKH (Pay to Public Key Hash)")
                print(f"  [*] PubKeyHash (20B): {shex[6:-4]}")
            elif shex.startswith("a914") and shex.endswith("87"):
                print(f"\n  [*] Script Type: P2SH (Pay to Script Hash)")
                print(f"  [*] ScriptHash (20B): {shex[4:-2]}")
            elif shex.startswith("0014"):
                print(f"\n  [*] Script Type: P2WPKH (Pay to Witness Public Key Hash)")
                print(f"  [*] WitnessHash: {shex[4:]}")
            elif shex.startswith("6a"):
                print("\n  [*] Script Type: OP_RETURN (data storage)")
            off += pklen

    off = print_field("[6] LOCKTIME", tx, off, 4, "Locktime (LE), 0=immediate",
                       f"Locktime = {int.from_bytes(tx[off-4:off], 'little')}")

    if off < total:
        print(f"\n{'='*90}")
        print(f"[FIELD] [7] WITNESS DATA | {total-off}B at offset {off}")
        print(f"{'='*90}")
        print(f"{'Offset':<8} {'Hex':<6} {'Binary (8 bits)':<80} {'Dec':<10}")
        print(f"{'-'*8} {'-'*6} {'-'*80} {'-'*10}")
        sn = min(80, total-off)
        for j in range(sn):
            bv = tx[off+j]
            print(f"{off+j:<8} 0x{bv:02x}  {bv:08b}    {bv:<10}")
        if total-off > 80:
            print(f"  ... ({total-off-80} more bytes)")

    print(f"\n{'='*90}")
    print(f"  TX PARSING DONE! Total: {total} bytes")
    print(f"{'='*90}")
    return tx

def parse_block(block_hex):
    """Parse Bitcoin block byte-by-byte"""
    blk = hex_to_bytes(block_hex)
    total = len(blk)
    off = 0
    print("\n" + "="*90)
    print("  BITCOIN BLOCK - BYTE-LEVEL PARSING  ")
    print("="*90)
    print(f"Total: {total} bytes ({total*2} hex chars)")
    print(f"Header: 80B, Body: {total-80}B")

    print(f"\n{'#'*90}\n### BLOCK HEADER (80 bytes) ###\n{'#'*90}")

    off = print_field("[1] BLOCK VERSION", blk, off, 4, "Block version (LE)",
                       f"Version = {int.from_bytes(blk[0:4], 'little')}")

    off = print_field("[2] PREV BLOCK HASH", blk, off, 32, "Prev block hash (internal rev)",
                       f"Prev Block = {blk[off-32:off][::-1].hex()}")

    off = print_field("[3] MERKLE ROOT", blk, off, 32, "Merkle root (internal rev)",
                       f"Merkle Root = {blk[off-32:off][::-1].hex()}")

    ts = int.from_bytes(blk[off:off+4], "little")
    try:
        ts_str = datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    except AttributeError:
        import calendar as _cal
        ts_str = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC") + " (legacy)"
    off = print_field("[4] TIMESTAMP", blk, off, 4, "UNIX timestamp (LE)",
                       f"Timestamp = {ts} -> {ts_str}")

    off = print_field("[5] BITS", blk, off, 4, "Difficulty target (compact)",
                       f"Bits = 0x{blk[off-4:off].hex()}")

    off = print_field("[6] NONCE", blk, off, 4, "Nonce (LE) for PoW",
                       f"Nonce = {int.from_bytes(blk[off-4:off], 'little')}")

    print("\n[*] Block header complete (80 bytes)")

    print(f"\n{'#'*90}\n### TRANSACTIONS ###\n{'#'*90}")

    tx_cnt, noff = read_varint(blk, off)
    vlen = noff - off
    print(f"\n[FIELD] TX COUNT = {tx_cnt} (VarInt, {vlen}B at offset {off})")
    for i in range(vlen):
        print(f"  {off+i}: 0x{blk[off+i]:02x} | {blk[off+i]:08b} | {blk[off+i]}")
    off = noff

    for txi in range(min(tx_cnt, 3)):
        print(f"\n{'#'*70}")
        print(f"### Block Tx #{txi+1}/{tx_cnt} (offset {off}) ###")
        print(f"{'#'*70}")

        tx_start = off
        o2 = 0

        if tx_start + 5 >= total:
            print("  [WARNING] Not enough data for transaction header, stopping")
            break

        marker = blk[tx_start+4] if tx_start+4 < total else 0
        flag = blk[tx_start+5] if tx_start+5 < total else 0
        is_sw = (marker == 0x00 and flag == 0x01)
        if is_sw: o2 += 6
        else: o2 += 4

        try:
            in_c, d = read_varint(blk, tx_start + o2); o2 += d
            for _ in range(in_c):
                if tx_start + o2 + 36 > total: raise IndexError("input bounds")
                o2 += 36
                if tx_start + o2 >= total: raise IndexError("scriptsig bounds")
                sl, sd = read_varint(blk, tx_start + o2); o2 += sd + sl
                if tx_start + o2 + 4 > total: raise IndexError("sequence bounds")
                o2 += 4
            out_c, d = read_varint(blk, tx_start + o2); o2 += d
            for _ in range(out_c):
                if tx_start + o2 + 8 > total: raise IndexError("value bounds")
                o2 += 8
                if tx_start + o2 >= total: raise IndexError("scriptpubkey bounds")
                pl, pd = read_varint(blk, tx_start + o2); o2 += pd + pl
            if tx_start + o2 + 4 > total: raise IndexError("locktime bounds")
            o2 += 4
            if is_sw:
                for _ in range(in_c):
                    if tx_start + o2 >= total: break
                    wc, wd = read_varint(blk, tx_start + o2); o2 += wd
                    for _ in range(wc):
                        if tx_start + o2 >= total: break
                        wl, w = read_varint(blk, tx_start + o2); o2 += w + wl
        except (IndexError, struct.error):
            print(f"  [WARNING] Error parsing transaction at offset {tx_start + o2}, skipping remaining")
            break

        tx_len = o2
        print(f"Tx length: {tx_len}B, offsets [{off} - {off+tx_len-1}]")
        print(f"\n{'Offset':<8} {'Hex':<6} {'Binary (8 bits)':<80} {'Dec':<10}")
        print(f"{'-'*8} {'-'*6} {'-'*80} {'-'*10}")

        sn = min(tx_len, 200)
        for j in range(sn):
            bv = blk[off+j]
            print(f"{off+j:<8} 0x{bv:02x}  {bv:08b}    {bv:<10}")
        if tx_len > 200:
            print(f"  ... ({tx_len-200} bytes omitted) ...")
            for j in range(max(200, tx_len-10), tx_len):
                bv = blk[off+j]
                print(f"{off+j:<8} 0x{bv:02x}  {bv:08b}    {bv:<10}")
        off += tx_len

    print(f"\n{'='*90}")
    print(f"  BLOCK PARSING DONE! {total}B, {tx_cnt} txs")
    print(f"{'='*90}")
    return blk

def show_bit_analysis(data_hex, title="Data"):
    """Display every single bit of each byte"""
    data = hex_to_bytes(data_hex)
    print(f"\n{'='*90}")
    print(f"  BIT-LEVEL ANALYSIS: {title}")
    print(f"{'='*90}")
    print(f"Total: {len(data)} bytes = {len(data)*8} bits\n")
    print(f"{'Byte#':<8} {'Hex':<6} {'b7 b6 b5 b4  b3 b2 b1 b0':<45} {'Dec':<6} {'ASCII'}")
    print(f"{'-'*8} {'-'*6} {'-'*45} {'-'*6} {'-'*6}")
    for i, b in enumerate(data):
        bs = f"{b:08b}"
        ascii_c = chr(b) if 32 <= b <= 126 else '.'
        print(f"{i:<8} 0x{b:02x}  {bs[:4]}  {bs[4:]:<40} {b:<6} {ascii_c}")
    print(f"\n  [*] Total: {len(data)} bytes, {len(data)*8} bits")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("="*60)
        print("  BITCOIN TRANSACTION / BLOCK BIT-LEVEL PARSER")
        print("="*60)
        print()
        print("Usage:")
        print("  python btc_parser_main.py tx <hex>       Parse transaction")
        print("  python btc_parser_main.py block <hex>    Parse block")
        print("  python btc_parser_main.py bits <hex>     Bit-level analysis")
        print("  python btc_parser_main.py demo           Demo with saved data")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "tx" and len(sys.argv) > 2:
        parse_transaction(sys.argv[2])
    elif cmd == "block" and len(sys.argv) > 2:
        parse_block(sys.argv[2])
    elif cmd == "bits" and len(sys.argv) > 2:
        show_bit_analysis(sys.argv[2])
    elif cmd == "demo":
        print("\n" + "="*70)
        print("  DEMO MODE: Parsing saved testnet data")
        print("="*70)

        for fname, title, parser in [
            ("tx_normal_raw_hex.txt", "TESTNET NORMAL TX", parse_transaction),
            ("tx_raw_hex.txt", "TESTNET COINBASE TX", parse_transaction)
        ]:
            try:
                with open(fname) as f:
                    data = f.read().strip()
                print(f"\n{'~'*70}")
                print(f"  {title}: {fname} ({len(data)} hex chars)")
                print(f"{'~'*70}")
                parser(data)
            except FileNotFoundError:
                print(f"\n[SKIP] {fname} not found")

        try:
            with open("block_raw_hex.txt") as f:
                blk_data = f.read().strip()
            print(f"\n{'~'*70}")
            print(f"  TESTNET BLOCK: {len(blk_data)} hex chars")
            print(f"{'~'*70}")
            parse_block(blk_data)
        except FileNotFoundError:
            print("\n[SKIP] block_raw_hex.txt not found")

        for fname, title in [
            ("tx_normal_raw_hex.txt", "Testnet Normal Transaction"),
            ("block_raw_hex.txt", "Testnet Block (first 200B)")
        ]:
            try:
                with open(fname) as f:
                    data = f.read().strip()
                if "block" in title:
                    data = data[:400]
                print(f"\n{'~'*70}")
                show_bit_analysis(data, title)
            except FileNotFoundError:
                pass
    else:
        print(f"Unknown command: {cmd}")
        print("Use 'demo' to run demo mode")

