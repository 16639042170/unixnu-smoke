#!/usr/bin/env python3
"""Minimal Android logical-partition (super.img) unpacker.

Handles Android sparse images and LP metadata v1.0/v1.2. Linear extents only.
"""
import argparse
import struct
import sys

GEOMETRY_MAGIC = 0x616C4467
HEADER_MAGIC = 0x414C5030
GEOMETRY_SIZE = 4096
RESERVED = 4096
SPARSE_MAGIC = 0xED26FF3A
SECTOR = 512


class SparseReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        hdr = self.f.read(28)
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic != SPARSE_MAGIC:
            raise SystemExit("not a sparse image")
        (_, _, _, self.fhdr_sz, self.chdr_sz, self.blk_sz,
         self.total_blks, self.total_chunks, _) = struct.unpack("<IHHHHIIII", hdr)
        self.f.seek(self.fhdr_sz)
        self.chunks = []
        pos = self.fhdr_sz
        for _ in range(self.total_chunks):
            self.f.seek(pos)
            ctype, size, total = struct.unpack("<HHI", self.f.read(8))
            self.chunks.append((pos + self.chdr_sz, ctype, size, total))
            pos += self.chdr_sz + total
        self.size = self.total_blks * self.blk_sz

    def read_at(self, offset, length):
        out = bytearray()
        end = offset + length
        for data_pos, ctype, size, total in self.chunks:
            pass
        # build an index of output ranges lazily
        raise SystemExit("sparse read_at not implemented")


class RawReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.f.seek(0, 2)
        self.size = self.f.tell()

    def read_at(self, offset, length):
        self.f.seek(offset)
        return self.f.read(length)


def sparse_to_raw(src, dst):
    """Expand an Android sparse image to a raw file."""
    f = open(src, "rb")
    hdr = f.read(28)
    (magic, major, minor, fhdr_sz, chdr_sz, blk_sz,
     total_blks, total_chunks, _crc) = struct.unpack("<IHHHHIIII", hdr)
    if magic != SPARSE_MAGIC:
        raise SystemExit("not sparse")
    print(f"sparse: blk={blk_sz} blocks={total_blks} chunks={total_chunks}")
    f.seek(fhdr_sz)
    out = open(dst, "wb")
    written = 0
    for _ in range(total_chunks):
        ctype, size, total = struct.unpack("<HHI", f.read(8))
        if ctype == 0xCAC1:          # raw
            remaining = size
            while remaining:
                chunk = f.read(min(remaining, 1 << 20))
                if not chunk:
                    raise SystemExit("truncated raw chunk")
                out.write(chunk)
                remaining -= len(chunk)
            written += size
        elif ctype == 0xCAC2:        # fill
            value = f.read(4)
            out.write(value * (size // 4))
            written += size
        elif ctype == 0xCAC3:        # dont care
            out.write(b"\0" * size)
            written += size
        elif ctype == 0xCAC4:        # crc32
            f.read(4)
        else:
            raise SystemExit(f"unknown chunk type {ctype:#x}")
    out.close()
    f.close()
    print(f"raw image: {written} bytes")


def parse_metadata(f):
    f.seek(RESERVED)
    geo = f.read(GEOMETRY_SIZE)
    magic, struct_size, _checksum, max_size, slot_count, logical_block = struct.unpack("<II32sIII", geo[:52])
    if magic != GEOMETRY_MAGIC:
        raise SystemExit(f"bad geometry magic {magic:#x}")
    print(f"geometry: max_size={max_size} slots={slot_count} logical_block={logical_block}")
    table = None
    for slot in range(slot_count):
        base = RESERVED + GEOMETRY_SIZE + slot * max_size
        f.seek(base)
        hdr = f.read(256)
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic != HEADER_MAGIC:
            continue
        major, minor, header_size, tables_size = struct.unpack("<HHII", hdr[4:16])
        parts, exts, groups, _devs = (struct.unpack("<III", hdr[80 + 12 * i:92 + 12 * i]) for i in range(4))
        print(f"header slot {slot}: v{major}.{minor} size={header_size} tables={tables_size}")
        table = (base, hdr, parts, exts, groups)
        break
    if table is None:
        raise SystemExit("no valid metadata header")
    return table


def read_tables(f, base, hdr, parts, exts):
    p_off, p_num, p_size = parts
    e_off, e_num, e_size = exts
    f.seek(base + p_off)
    pdata = f.read(p_num * p_size)
    f.seek(base + e_off)
    edata = f.read(e_num * e_size)
    plist = []
    for i in range(p_num):
        ent = pdata[i * p_size:(i + 1) * p_size]
        name = ent[:36].split(b"\0")[0].decode("utf-8", "replace")
        attrs, first_ext, num_ext, group = struct.unpack("<IIII", ent[36:52])
        plist.append((name, first_ext, num_ext))
    elist = []
    for i in range(e_num):
        ent = edata[i * e_size:(i + 1) * e_size]
        num_sectors = struct.unpack("<Q", ent[:8])[0]
        target_type = struct.unpack("<I", ent[8:12])[0]
        if e_size >= 24:
            target_data = struct.unpack("<Q", ent[12:20])[0] if e_size == 24 else struct.unpack("<Q", ent[16:24])[0]
        else:
            target_data = struct.unpack("<Q", ent[12:20])[0]
        elist.append((num_sectors, target_type, target_data))
    return plist, elist


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("super_img")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--extract", default=None, help="partition name prefix to extract")
    ap.add_argument("--out", default="partition.img")
    args = ap.parse_args()

    src = args.super_img
    with open(src, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
    if magic == SPARSE_MAGIC:
        raw = src + ".raw"
        sparse_to_raw(src, raw)
        src = raw

    f = open(src, "rb")
    f.seek(0, 2)
    total = f.tell()
    base, hdr, parts, exts, groups = parse_metadata(f)
    plist, elist = read_tables(f, base, hdr, parts, exts)
    print(f"partitions: {len(plist)}")
    for name, first_ext, num_ext in plist:
        sectors = sum(elist[i][0] for i in range(first_ext, first_ext + num_ext))
        print(f"  {name:<24} {sectors * SECTOR / (1024**2):8.1f} MiB  extents={num_ext}")
    if args.list:
        return
    if not args.extract:
        return
    match = [p for p in plist if p[0] == args.extract or p[0].startswith(args.extract + "_")]
    if not match:
        raise SystemExit(f"partition {args.extract} not found")
    name, first_ext, num_ext = match[0]
    print(f"extracting {name} -> {args.out}")
    with open(args.out, "wb") as out:
        for i in range(first_ext, first_ext + num_ext):
            num_sectors, target_type, target_data = elist[i]
            size = num_sectors * SECTOR
            if target_type == 1:      # ZERO
                out.write(b"\0" * size)
                continue
            if target_type != 0:
                raise SystemExit(f"unsupported extent target {target_type}")
            offset = target_data * SECTOR
            if offset + size > total:
                raise SystemExit("extent past end of image")
            f.seek(offset)
            remaining = size
            while remaining:
                chunk = f.read(min(remaining, 1 << 22))
                if not chunk:
                    raise SystemExit("short read")
                out.write(chunk)
                remaining -= len(chunk)
    import os
    print(f"wrote {args.out}: {os.path.getsize(args.out)} bytes")


if __name__ == "__main__":
    main()
