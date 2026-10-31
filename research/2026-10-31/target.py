import ctypes, os, sys, time
secret = bytearray(b'TOPSECRET-' + b'k' * 22)
if sys.argv[1] == '0':
    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 4
print(os.getpid(), flush=True); time.sleep(30)
