
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Optional, Iterator, Dict, Any
import struct, json, re

try:
    import snappy as _snappy
    _HAS_SNAPPY = True
except Exception:
    _snappy = None
    _HAS_SNAPPY = False

def read_varint(buf: memoryview, pos: int) -> Tuple[int, int]:
    x = 0; shift = 0
    while True:
        b = buf[pos]; pos += 1
        x |= (b & 0x7F) << shift
        if (b & 0x80) == 0: return x, pos
        shift += 7
        if shift > 63: raise ValueError("varint too long")

@dataclass
class BlockHandle:
    offset: int
    size: int

FOOTER_SIZE = 48
LEVELDB_MAGIC = 0xdb4775248b80fb57  # little-endian

def parse_footer(mm: memoryview) -> Tuple[BlockHandle, BlockHandle]:
    if len(mm) < FOOTER_SIZE:
        raise ValueError("file too small for footer")
    foot = mm[-FOOTER_SIZE:]
    pos = 0
    off1, pos = read_varint(foot, pos)
    size1, pos = read_varint(foot, pos)
    off2, pos = read_varint(foot, pos)
    size2, pos = read_varint(foot, pos)
    magic = struct.unpack_from("<Q", foot, FOOTER_SIZE-8)[0]
    if magic != LEVELDB_MAGIC:
        raise ValueError(f"bad magic: {magic:#x}")
    return BlockHandle(off1, size1), BlockHandle(off2, size2)

def read_block(mm: memoryview, bh: BlockHandle) -> bytes:
    start = bh.offset; end = bh.offset + bh.size
    data = mm[start:end]
    comp = mm[end]
    if comp == 0:
        return bytes(data)
    elif comp == 1:
        if not _HAS_SNAPPY:
            raise RuntimeError("snappy-compressed block but python-snappy not installed")
        return _snappy.decompress(bytes(data))
    else:
        raise RuntimeError(f"unsupported compression {comp}")

def parse_restarts(block: bytes) -> Tuple[List[int], int]:
    if len(block) < 4: raise ValueError("block too small")
    num = struct.unpack_from("<I", block, len(block)-4)[0]
    arr_sz = 4 * num
    if len(block) < 4 + arr_sz: raise ValueError("restart array truncated")
    restarts = list(struct.unpack_from("<" + "I"*num, block, len(block)-4-arr_sz))
    data_end = len(block) - 4 - arr_sz
    return restarts, data_end

def entries_from_block(block: bytes) -> Iterator[Tuple[bytes, bytes]]:
    restarts, data_end = parse_restarts(block)
    pos = 0; last_key = b""
    mv = memoryview(block)
    while pos < data_end:
        shared, pos = read_varint(mv, pos)
        non_shared, pos = read_varint(mv, pos)
        vlen, pos = read_varint(mv, pos)
        key_suffix = block[pos:pos+non_shared]; pos += non_shared
        value = block[pos:pos+vlen]; pos += vlen
        if shared > len(last_key): raise ValueError("shared>last_key")
        key = last_key[:shared] + key_suffix
        yield key, bytes(value)
        last_key = key

def iterate_table(path: str) -> Iterator[Tuple[bytes, bytes]]:
    with open(path, "rb") as f: data = f.read()
    mm = memoryview(data)
    meta, index = parse_footer(mm)
    index_raw = read_block(mm, index)
    restarts, data_end = parse_restarts(index_raw)
    pos = 0; last_key = b""; mv = memoryview(index_raw)
    while pos < data_end:
        shared, pos = read_varint(mv, pos)
        non_shared, pos = read_varint(mv, pos)
        vlen, pos = read_varint(mv, pos)
        ks = index_raw[pos:pos+non_shared]; pos += non_shared
        v = index_raw[pos:pos+vlen]; pos += vlen
        if shared > len(last_key): raise ValueError("index shared>last_key")
        key = last_key[:shared] + ks; last_key = key
        mvv = memoryview(v)
        off, p2 = read_varint(mvv, 0)
        sz, p2 = read_varint(mvv, p2)
        dblock = read_block(mm, BlockHandle(off, sz))
        for k, val in entries_from_block(dblock):
            yield k, val

# ---- Internal key decode ----
TYPE_MAP = {0: "deletion", 1: "value", 2: "merge", 3: "log"}

def split_internal_key(k: bytes) -> Dict[str, Any]:
    if len(k) < 8:
        return {"user_key": k, "seq": None, "type": None}
    tag_le = int.from_bytes(k[-8:], "little", signed=False)
    type_id = tag_le & 0xFF
    seq = tag_le >> 8
    user = k[:-8]
    return {"user_key": user, "seq": seq, "type_id": type_id, "type": TYPE_MAP.get(type_id, f"unknown({type_id})")}

# ---- Value decoding ----
ASCII_TOKEN_RE = re.compile(rb"[A-Za-z0-9._:-]{4,}")

def try_utf8(b: bytes) -> Optional[str]:
    try:
        return b.decode("utf-8")
    except Exception:
        return None

def try_json_text(txt: str) -> Optional[str]:
    try:
        j = json.loads(txt)
        return json.dumps(j, ensure_ascii=False, indent=2)
    except Exception:
        return None

def extract_ascii_keywords(b: bytes, max_items: int = 128) -> List[str]:
    toks = ASCII_TOKEN_RE.findall(b)
    out, seen = [], set()
    for t in toks:
        s = t.decode("utf-8", errors="ignore")
        if s and s not in seen:
            seen.add(s); out.append(s)
        if len(out) >= max_items:
            break
    return out

def decode_protobuf_best_effort(b: bytes, max_fields: int = 120) -> List[Dict[str, Any]]:
    res = []
    mv = memoryview(b)
    pos = 0; n = 0
    try:
        while pos < len(mv) and n < max_fields:
            key, pos = read_varint(mv, pos)
            field_no = key >> 3
            wt = key & 7
            entry = {"field": field_no, "wire": wt}
            if wt == 0:  # varint
                v, pos = read_varint(mv, pos)
                entry["value"] = v
            elif wt == 1:  # 64-bit
                if pos+8 > len(mv): break
                raw = bytes(mv[pos:pos+8]); pos += 8
                entry["fixed64_le"] = int.from_bytes(raw, "little", signed=False)
            elif wt == 2:  # length-delimited
                ln, pos = read_varint(mv, pos)
                raw = bytes(mv[pos:pos+ln]); pos += ln
                s = try_utf8(raw)
                if s is not None:
                    entry["string"] = s
                    j = try_json_text(s)
                    if j is not None:
                        entry["json"] = j
                else:
                    entry["bytes_hex"] = raw.hex()
            elif wt == 5:  # 32-bit
                if pos+4 > len(mv): break
                raw = bytes(mv[pos:pos+4]); pos += 4
                entry["fixed32_le"] = int.from_bytes(raw, "little", signed=False)
            else:
                entry["unsupported_wire_type"] = wt
                break
            res.append(entry); n += 1
    except Exception:
        pass
    return res

def decode_value_best(b: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "len": len(b),
        "raw_bytes": b,
        "raw_ascii": "".join(chr(c) if 32 <= c <= 126 else "." for c in b)
    }
    s = try_utf8(b)
    if s is not None:
        j = try_json_text(s)
        if j is not None:
            out["kind"] = "json"
            out["json"] = j
            out["text"] = s
            out["keywords"] = extract_ascii_keywords(b)
            return out
        out["kind"] = "utf8"
        out["text"] = s
        out["keywords"] = extract_ascii_keywords(b)
        pb = decode_protobuf_best_effort(b[:4096], max_fields=80)
        if pb:
            out["protobuf_guess"] = pb
        return out
    pb = decode_protobuf_best_effort(b, max_fields=120)
    if pb:
        out["kind"] = "protobuf"
        out["protobuf"] = pb
        return out
    out["kind"] = "bytes"
    out["hex_head"] = b.hex()
    return out
