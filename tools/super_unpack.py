#!/usr/bin/env python3
"""Minimal Android logical-partition (super.img) unpacker.

Reads Android sparse images on demand (no expansion) and LP metadata v1.x.
Only LINEAR extents are supported.
"""
import argparse
import os
import struct

GEOMETRY_MAGIC = 0x616C4467
HEADER_MAGIC = 0x414C5030
GEOMETRY_SIZE = 4096
RESERVED = 4096
SPARSE_MAGIC = 0xED26FF3A
SECTOR = 512
CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4


class RawReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.f.seek(0, 2)
        self.size = self.f.tell()

    def read_at(self, offset, length):
        self.f.seek(offset)
        return self.f.read(length)


class SparseReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        hdr = self.f.read(28)
        (magic, major, minor, fhdr_sz, chdr_sz, blk_sz,
         total_blks, total_chunks, _crc) = struct.unpack("<IHHHHIIII", hdr)
        if magic != SPARSE_MAGIC:
            raise SystemExit("not a sparse image")
        self.size = total_blks * blk_sz
        print(f"sparse: block={blk_sz} blocks={total_blks} chunks={total_chunks}", flush=True)
        self.chunks = []
        pos = fhdr_sz
        out = 0
        for _ in range(total_chunks):
            self.f.seek(pos)
            ctype, _res, size, total = struct.unpack("<HHII", self.f.read(12))
            self.chunks.append((out, out + size, ctype, pos + chdr_sz))
            out += size
            pos += total
        if out != self.size:
            raise SystemExit(f"sparse size mismatch: {out} != {self.size}")

    def read_at(self, offset, length):
        buf = bytearray(length)
        end = offset + length
        for start, cend, ctype, data_off in self.chunks:
            if cend <= offset:
                continue
            if start >= end:
                break
            lo, hi = max(offset, start), min(end, cend)
            n = hi - lo
            dst = slice(lo - offset, hi - offset)
            if ctype == CHUNK_RAW:
                self.f.seek(data_off + (lo - start))
                buf[dst] = self.f.read(n)
            elif ctype == CHUNK_FILL:
                self.f.seek(data_off)
                value = self.f.read(4)
                buf[dst] = (value * ((n + 3) // 4))[:n]
            elif ctype in (CHUNK_DONT_CARE, CHUNK_CRC32):
                pass
            else:
                raise SystemExit(f"unknown chunk type {ctype:#x}")
        return bytes(buf)


def open_reader(path):
    with open(path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
    if magic == SPARSE_MAGIC:
        return SparseReader(path)
    return RawReader(path)


def parse_metadata(reader):
    geo = reader.read_at(RESERVED, GEOMETRY_SIZE)
    magic, struct_size, _checksum, max_size, slot_count, logical_block = struct.unpack("<II32sIII", geo[:52])
    if magic != GEOMETRY_MAGIC:
        raise SystemExit(f"bad geometry magic {magic:#x}")
    print(f"geometry: max_size={max_size} slots={slot_count} logical_block={logical_block}", flush=True)
    for slot in range(slot_count):
        base = RESERVED + GEOMETRY_SIZE + slot * max_size
        hdr = reader.read_at(base, 256)
        if struct.unpack("<I", hdr[:4])[0] != HEADER_MAGIC:
            continue
        major, minor, header_size, tables_size = struct.unpack("<HHII", hdr[4:16])
        parts = struct.unpack("<III", hdr[80:92])
        exts = struct.unpack("<III", hdr[92:104])
        print(f"header slot {slot}: v{major}.{minor} header={header_size} tables={tables_size}", flush=True)
        return base, hdr, parts, exts
    raise SystemExit("no valid metadata header")


def read_tables(reader, base, parts, exts):
    p_off, p_num, p_size = parts
    e_off, e_num, e_size = exts
    pdata = reader.read_at(base + p_off, p_num * p_size)
    edata = reader.read_at(base + e_off, e_num * e_size)
    plist = []
    for i in range(p_num):
        ent = pdata[i * p_size:(i + 1) * p_size]
        name = ent[:36].split(b"\0")[0].decode("utf-8", "replace")
        _attrs, first_ext, num_ext, _group = struct.unpack("<IIII", ent[36:52])
        plist.append((name, first_ext, num_ext))
    elist = []
    for i in range(e_num):
        ent = edata[i * e_size:(i + 1) * e_size]
        num_sectors = struct.unpack("<Q", ent[:8])[0]
        target_type = struct.unpack("<I", ent[8:12])[0]
        # packed: target_data at 12; aligned layout: at 16
        if e_size >= 24:
            target_data = struct.unpack("<Q", ent[12:20])[0]
        else:
            target_data = struct.unpack("<Q", ent[12:20])[0]
        elist.append((num_sectors, target_type, target_data))
    return plist, elist


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("super_img")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--extract", default=None)
    ap.add_argument("--out", default="partition.img")
    args = ap.parse_args()

    reader = open_reader(args.super_img)
    print(f"image size: {reader.size} bytes", flush=True)
    base, hdr, parts, exts = parse_metadata(reader)
    plist, elist = read_tables(reader, base, parts, exts)
    print(f"partitions: {len(plist)}", flush=True)
    for name, first_ext, num_ext in plist:
        sectors = sum(elist[i][0] for i in range(first_ext, first_ext + num_ext))
        print(f"  {name:<24} {sectors * SECTOR / (1024**2):9.1f} MiB  extents={num_ext}", flush=True)

    if args.list or not args.extract:
        return

    match = [p for p in plist if p[0] == args.extract or p[0].startswith(args.extract + "_")]
    if not match:
        raise SystemExit(f"partition {args.extract} not found")
    name, first_ext, num_ext = match[0]
    print(f"extracting {name} -> {args.out}", flush=True)
    with open(args.out, "wb") as out:
        for i in range(first_ext, first_ext + num_ext):
            num_sectors, target_type, target_data = elist[i]
            size = num_sectors * SECTOR
            if target_type == 1:
                out.write(b"\0" * size)
                continue
            if target_type != 0:
                raise SystemExit(f"unsupported extent target {target_type}")
            offset = target_data * SECTOR
            if offset + size > reader.size:
                raise SystemExit("extent past end of image")
            step = 1 << 22
            for chunk_off in range(0, size, step):
                n = min(step, size - chunk_off)
                out.write(reader.read_at(offset + chunk_off, n))
    print(f"wrote {args.out}: {os.path.getsize(args.out)} bytes", flush=True)


if __name__ == "__main__":
    main()
