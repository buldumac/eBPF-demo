#!/bin/bash


printf hacked > /proc/self/comm

for i in $(seq 1 100); do
    echo "$i" > "abc-$i.txt"
    if (( i % 5 == 0 )); then
	    python3 -c "import mmap; m=mmap.mmap(-1,4096); print('mmap ok'); m.close()"
    fi
    sleep 1
done
