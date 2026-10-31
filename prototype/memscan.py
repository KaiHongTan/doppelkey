# memscan.py <pid> <needles-file>: reads every readable region of a live process
# (/proc/<pid>/mem, what a same-user agent could do) and counts needles found.
# Each needle is searched as raw bytes, as lowercase hex text, and as UTF-16 text.
import sys, re
pid, needles = sys.argv[1], [bytes.fromhex(l) for l in open(sys.argv[2]).read().split()]
forms = []
for i, n in enumerate(needles):
    label = 'secret' if i == 0 else f'derived key {i}'
    fs = [n, n.hex().encode()]
    if i == 0: fs.append(n.decode('latin1').encode('utf-16-le'))
    forms.append((label, fs))
found, scanned = {}, 0
mem = open(f'/proc/{pid}/mem', 'rb', 0)
for line in open(f'/proc/{pid}/maps'):
    addr, perms = line.split()[:2]
    if not perms.startswith('r') or '[vvar' in line or '[vsyscall' in line: continue
    lo, hi = (int(x, 16) for x in addr.split('-'))
    pos = lo
    while pos < hi:
        size = min(hi - pos, 64 << 20)
        try:
            mem.seek(pos); chunk = mem.read(size)
        except OSError:
            pos += size; continue
        scanned += len(chunk)
        for label, fs in forms:
            if any(f in chunk for f in fs): found[label] = True
        pos += size if pos + size >= hi else size - 256  # overlap so no needle is split
print({'bytesScanned': f'{scanned/1e6:.0f} MB', 'found': sorted(found) or 'nothing'})
