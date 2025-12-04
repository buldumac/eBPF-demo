package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	taskCommLen = 16
)

// Must match struct event in monitor.bpf.c 1:1
type Event struct {
	Pid       uint32
	Ppid      uint32
	Uid       uint32
	Type      uint32
	Comm      [taskCommLen]byte
	Filename  [256]byte
	Daddr     uint32
	Dport     uint16
	Pad       uint16
	Count     uint64
	MmapAddr  uint64
	MmapLen   uint64
	MmapProt  uint32
	MmapFlags uint32
}

func ntohs(p uint16) uint16 {
	return (p<<8 | p>>8)
}

func printIPv4(addr uint32, port uint16) string {
	if addr == 0 {
		return "0.0.0.0:0"
	}
	// addr is in network byte order already; treat as big endian
	ipBytes := []byte{
		byte(addr),
		byte(addr >> 8),
		byte(addr >> 16),
		byte(addr >> 24),
	}
	ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
	return fmt.Sprintf("%s:%d", ip.String(), ntohs(port))
}

func printLenMmapHuman(n uint64) string {
	const KB = 1024.0
	const MB = 1024.0 * 1024.0

	if n >= 1<<20 {
		return fmt.Sprintf("%.2f MB", float64(n)/MB)
	}
	if n >= 1024 {
		return fmt.Sprintf("%.2f KB", float64(n)/KB)
	}
	return fmt.Sprintf("%d B", n)
}

// helper to attach one tracepoint
func attachTP(prog *ebpf.Program, group, name string) (link.Link, error) {
	return link.Tracepoint(group, name, prog, nil)
}

func main() {
	objPath := flag.String("obj", "monitor.bpf.o", "path to eBPF object")
	filterComm := flag.String("comm", "", "filter by comm (exact match)")
	flag.Parse()

	// Allow locking memory for maps/programs
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("RemoveMemlock: %v", err)
	}

	// Load collection spec from the .o file
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("LoadCollectionSpec(%s): %v", *objPath, err)
	}

	// Struct to bind maps/programs by name from the spec
	var objs struct {
		HandleConnect *ebpf.Program `ebpf:"handle_connect"`
		HandleOpenat  *ebpf.Program `ebpf:"handle_openat"`
		HandleWrite   *ebpf.Program `ebpf:"handle_write"`
		HandleRename  *ebpf.Program `ebpf:"handle_rename"`
		HandleRenameAt *ebpf.Program `ebpf:"handle_renameat"`
		HandleMmap    *ebpf.Program `ebpf:"handle_mmap"`

		Events *ebpf.Map `ebpf:"events"`
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("LoadAndAssign: %v", err)
	}
	defer objs.HandleConnect.Close()
	defer objs.HandleOpenat.Close()
	defer objs.HandleWrite.Close()
	defer objs.HandleRename.Close()
	defer objs.HandleRenameAt.Close()
	defer objs.HandleMmap.Close()
	defer objs.Events.Close()

	// Attach all tracepoints
	var links []link.Link

	addLink := func(l link.Link, err error) {
		if err != nil {
			log.Fatalf("attach tracepoint: %v", err)
		}
		links = append(links, l)
	}

	addLink(attachTP(objs.HandleConnect, "syscalls", "sys_enter_connect"))
	addLink(attachTP(objs.HandleOpenat, "syscalls", "sys_enter_openat"))
	addLink(attachTP(objs.HandleWrite, "syscalls", "sys_enter_write"))
	addLink(attachTP(objs.HandleRenameAt, "syscalls", "sys_enter_renameat"))
	addLink(attachTP(objs.HandleRename, "syscalls", "sys_enter_rename"))
	addLink(attachTP(objs.HandleMmap, "syscalls", "sys_enter_mmap"))

	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	// Ringbuf reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("NewReader(events): %v", err)
	}
	defer rd.Close()

	fmt.Println("Attached. Monitoring connect/open/write/rename/mmap.")
	if *filterComm != "" {
		fmt.Printf("Filtering by comm=\"%s\".\n", *filterComm)
	}
	fmt.Println("Press Ctrl-C to exit.\n")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			// timeout / deadline etc. – just continue
			continue
		}

		// Parse event from RawSample
		var e Event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}

		comm := strings.TrimRight(string(e.Comm[:]), "\x00")
		if *filterComm != "" && comm != *filterComm {
			continue
		}

		ts := time.Now().Format("15:04:05")
		fmt.Printf("[%s] pid=%d ppid=%d uid=%d comm=%s ", ts, e.Pid, e.Ppid, e.Uid, comm)

		switch e.Type {
		case 0:
			fmt.Printf("EVENT=connect dst=%s", printIPv4(e.Daddr, e.Dport))
		case 1:
			path := strings.TrimRight(string(e.Filename[:]), "\x00")
			fmt.Printf("EVENT=open    path=%s", path)
		case 2:
			fmt.Printf("EVENT=write   bytes=%d", e.Count)
		case 3:
			path := strings.TrimRight(string(e.Filename[:]), "\x00")
			fmt.Printf("EVENT=rename  newpath=%s", path)
		case 4:
			fmt.Printf("EVENT=mmap    addr=0x%x len=%s prot=0x%x flags=0x%x",
				e.MmapAddr, printLenMmapHuman(e.MmapLen), e.MmapProt, e.MmapFlags)
		default:
			fmt.Printf("EVENT=unknown(%d)", e.Type)
		}

		fmt.Println()
	}
}

