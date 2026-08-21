import os
import signal
import sys
import time

ready_read, ready_write = os.pipe()
child = os.fork()
if child:
    os.close(ready_write)
    os.read(ready_read, 1)
    os.close(ready_read)
    time.sleep(0.2)
    raise SystemExit(0)

os.close(ready_read)
os.setsid()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(sys.argv[1], "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
    output.flush()
os.write(ready_write, b"1")
os.close(ready_write)

while True:
    time.sleep(1)
