import sys, ctypes, os
pid = int(sys.argv[1]); out = {}
try: out['environ'] = len(open(f'/proc/{pid}/environ','rb').read())
except Exception as e: out['environ'] = type(e).__name__
try:
    mem = open(f'/proc/{pid}/mem','rb',0); hits = 0
    for line in open(f'/proc/{pid}/maps'):
        a, p = line.split()[:2]
        if not p.startswith('r') or 'vvar' in line or 'vsyscall' in line: continue
        lo, hi = (int(x,16) for x in a.split('-'))
        try: mem.seek(lo); hits += b'TOPSECRET-kkkk' in mem.read(hi-lo)
        except OSError: pass
    out['mem_found'] = bool(hits)
except Exception as e: out['mem'] = type(e).__name__
libc = ctypes.CDLL(None, use_errno=True)
out['ptrace_attach'] = 'ok' if libc.ptrace(16, pid, 0, 0) == 0 else os.strerror(ctypes.get_errno())
print(out)
