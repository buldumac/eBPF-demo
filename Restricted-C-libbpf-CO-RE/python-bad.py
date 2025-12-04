#!/usr/bin/env python3

import socket
import mmap
import os
import time

# -------------------------------------------------
# Rename the process comm to "hacked" to filter process with eBPF user-space loader
# -------------------------------------------------
with open("/proc/self/comm", "wb") as f:
    f.write(b"hacked")   # no newline, <= 15 chars

# -------------------------------------------------
# Create target directory if missing
# -------------------------------------------------
DIR = "very-important-files"
os.makedirs(DIR, exist_ok=True)

# -------------------------------------------------
# Create 10 files: hello-hello-1 ... hello-hello-10
# (each 1 second apart)
# -------------------------------------------------
for i in range(1, 5):
    path = os.path.join(DIR, f"hello-hello-{i}")
    with open(path, "w") as f:
        f.write(str(i))
    time.sleep(1)

# -------------------------------------------------
# 1. Connect to 8.8.8.8:53 and instantly drop
# -------------------------------------------------
def quick_connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        s.connect(("8.8.8.8", 53))
    except Exception:
        pass
    s.close()

time.sleep(2)
quick_connect()

# -------------------------------------------------
# 2. mmap 5678 bytes, close it, repeat 4 times
# -------------------------------------------------
for _ in range(4):
    m = mmap.mmap(-1, 5678)
    m.close()
time.sleep(3)
# -------------------------------------------------
# 3. Connect 5 more times
# -------------------------------------------------
for _ in range(5):
    quick_connect()

# -------------------------------------------------
# 4. Create 100 files inside DIR: hello-exe-1..100
# -------------------------------------------------
filenames = []
for i in range(1, 101):
    name = f"hello-exe-{i}"
    path = os.path.join(DIR, name)

    with open(path, "w") as f:
        f.write(str(i))

    filenames.append(path)
    time.sleep(0.05)

# -------------------------------------------------
# 5. Rename all using renameat (syscall renameat)
# -------------------------------------------------
AT_FDCWD = -100

for old_path in filenames:
    new_path = old_path + ".encrypted"
    os.rename(old_path, new_path, src_dir_fd=AT_FDCWD, dst_dir_fd=AT_FDCWD)
    time.sleep(0.05)
