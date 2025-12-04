rm /usr/sbin/bpftool

apt update && apt install -y git
cd / && git clone --recurse-submodules https://github.com/libbpf/bpftool.git

cd bpftool/src
make install

ln -s /usr/local/sbin/bpftool /usr/sbin/bpftool
