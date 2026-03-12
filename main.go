package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Build BPF object first, for example:
// clang -O2 -g -target bpf -c bpf/flow.c -o bpf/flow.o
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" flow ./bpf/flow.c -- -I/usr/include

type crictlPS struct {
	Containers []struct {
		ID    string `json:"id"`
		Image struct {
			Image string `json:"image"`
		} `json:"image"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"containers"`
}

type event struct {
	TsNs      uint64
	ImageSlot uint32
	Saddr     uint32
	Daddr     uint32
	Sport     uint16
	Dport     uint16
	PktLen    uint16
	Proto     uint8
	Dir       uint8
}

type assoc struct {
	Identity      string
	ContainerName string
	PodName       string
	Namespace     string
	PID           int
	Cgroup        string
}

type attachRef struct {
	col *ebpf.Collection
	egr link.Link
	objs *flowObjects
	egr  link.Link
}

type flowKey struct {
	Namespace, PodName, ContainerName, Dir, Proto, SrcIP, DstIP string
	SrcPort, DstPort                                            uint16
}

type metric struct {
	Packets uint64
	Bytes   uint64
}

type manager struct {
	mu       sync.Mutex
	slotSeq  uint32
	idToSlot map[string]uint32
	slotToID map[uint32]string
	refs     map[string]*attachRef
	rbMap    *ebpf.Map
}

func newManager(rbMap *ebpf.Map) *manager {
	return &manager{
		slotSeq:  1,
		idToSlot: map[string]uint32{},
		slotToID: map[uint32]string{},
		refs:     map[string]*attachRef{},
		rbMap:    rbMap,
	}
}

func (m *manager) slot(identity string) uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.idToSlot[identity]; ok {
		return s
	}
	s := m.slotSeq
	m.slotSeq++
	m.idToSlot[identity] = s
	m.slotToID[s] = identity
	return s
}

func (m *manager) identity(slot uint32) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.slotToID[slot]
}

func (m *manager) sync(as []assoc) {
	desired := map[string]assoc{}
	for _, a := range as {
		desired[a.Identity+"|"+a.Cgroup] = a
	}

	m.mu.Lock()
	current := map[string]*attachRef{}
	for k, v := range m.refs {
		current[k] = v
	}
	m.mu.Unlock()

	for k, a := range desired {
		if _, ok := current[k]; ok {
			continue
		}
		if err := m.attach(a); err != nil {
			fmt.Fprintf(os.Stderr, "attach failed identity=%q cgroup=%q: %v\n", a.Identity, a.Cgroup, err)
		}
	}

	for k, ref := range current {
		if _, ok := desired[k]; ok {
			continue
		}
		_ = ref.egr.Close()
		_ = ref.col.Close()
		_ = ref.objs.Close()
		m.mu.Lock()
		delete(m.refs, k)
		m.mu.Unlock()
	}
}

func (m *manager) attach(a assoc) error {
	col, prog, err := loadEgressProgram(m.slot(a.Identity), m.rbMap)
	if err != nil {
		return err
	}

	egr, err := link.AttachCgroup(link.CgroupOptions{Path: a.Cgroup, Attach: ebpf.AttachCGroupInetEgress, Program: prog})
	if err != nil {
		_ = col.Close()
	spec, err := loadFlow()
	if err != nil {
		return err
	}
	if err := spec.RewriteConstants(map[string]any{"image_slot": m.slot(a.Identity)}); err != nil {
		return err
	}

	objs := flowObjects{}
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"events": m.rbMap}}); err != nil {
		return err
	}

	egr, err := link.AttachCgroup(link.CgroupOptions{Path: a.Cgroup, Attach: ebpf.AttachCGroupInetEgress, Program: objs.CgroupEgress})
	if err != nil {
		_ = objs.Close()
		return err
	}

	m.mu.Lock()
	m.refs[a.Identity+"|"+a.Cgroup] = &attachRef{col: col, egr: egr}
	m.refs[a.Identity+"|"+a.Cgroup] = &attachRef{objs: &objs, egr: egr}
	m.mu.Unlock()

	fmt.Printf("attached egress namespace=%q pod=%q container=%q pid=%d cgroup=%s\n", a.Namespace, a.PodName, a.ContainerName, a.PID, a.Cgroup)
	return nil
}

func (m *manager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ref := range m.refs {
		_ = ref.egr.Close()
		_ = ref.col.Close()
		_ = ref.objs.Close()
	}
}

func main() {
	if os.Geteuid() != 0 {
		die("run as root")
	}
	if _, err := exec.LookPath("crictl"); err != nil {
		die("crictl not found: %v", err)
	}

	rbMap, err := ebpf.NewMap(&ebpf.MapSpec{Name: "events", Type: ebpf.RingBuf, MaxEntries: 1 << 24})
	if err != nil {
		die("create ringbuf map: %v", err)
	}
	defer rbMap.Close()

	rdr, err := ringbuf.NewReader(rbMap)
	if err != nil {
		die("open ringbuf reader: %v", err)
	}
	defer rdr.Close()

	mgr := newManager(rbMap)
	defer mgr.close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	assocs, err := discover()
	if err != nil {
		die("discover: %v", err)
	}
	mgr.sync(assocs)

	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				as, err := discover()
				if err != nil {
					fmt.Fprintf(os.Stderr, "discover: %v\n", err)
					continue
				}
				mgr.sync(as)
			}
		}
	}()

	metrics := map[flowKey]*metric{}
	printTicker := time.NewTicker(10 * time.Second)
	defer printTicker.Stop()

	go func() {
		<-ctx.Done()
		_ = rdr.Close()
	}()

	for {
		select {
		case <-printTicker.C:
			printMetrics(metrics)
		default:
		}

		rec, err := rdr.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				printMetrics(metrics)
				return
			}
			continue
		}

		var e event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}

		identity := mgr.identity(e.ImageSlot)
		namespace, podName, containerName := splitIdentity(identity)
		if identity == "" {
			namespace = "unknown"
			podName = "unknown"
			containerName = fmt.Sprintf("slot_%d", e.ImageSlot)
		}

		k := flowKey{
			Namespace:     namespace,
			PodName:       podName,
			ContainerName: containerName,
			Dir:           "egress",
			Proto:         proto(e.Proto),
			SrcIP:         ip(e.Saddr),
			DstIP:         ip(e.Daddr),
			SrcPort:       e.Sport,
			DstPort:       e.Dport,
		}
		m := metrics[k]
		if m == nil {
			m = &metric{}
			metrics[k] = m
		}
		m.Packets++
		m.Bytes += uint64(e.PktLen)
	}
}

func loadEgressProgram(identitySlot uint32, sharedEvents *ebpf.Map) (*ebpf.Collection, *ebpf.Program, error) {
	spec, err := ebpf.LoadCollectionSpec("bpf/flow.o")
	if err != nil {
		return nil, nil, fmt.Errorf("load bpf object bpf/flow.o: %w", err)
	}
	if err := spec.RewriteConstants(map[string]any{"image_slot": identitySlot}); err != nil {
		return nil, nil, fmt.Errorf("rewrite image_slot constant: %w", err)
	}

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"events": sharedEvents},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create bpf collection: %w", err)
	}

	prog, ok := col.Programs["cgroup_egress"]
	if !ok {
		_ = col.Close()
		return nil, nil, errors.New("cgroup_egress program not found in bpf object")
	}
	return col, prog, nil
}

func discover() ([]assoc, error) {
	out, err := exec.Command("crictl", "ps", "-o", "json").Output()
	if err != nil {
		return nil, err
	}
	var ps crictlPS
	if err := json.Unmarshal(out, &ps); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	res := make([]assoc, 0, len(ps.Containers))
	for _, c := range ps.Containers {
		pid, labels, err := inspectMetadata(c.ID)
		if err != nil || pid <= 0 {
			continue
		}

		// Only keep Kubernetes workloads that expose these standard CRI labels.
		containerName := labels["io.kubernetes.container.name"]
		podName := labels["io.kubernetes.pod.name"]
		namespace := labels["io.kubernetes.pod.namespace"]
		if containerName == "" || podName == "" || namespace == "" {
			continue
		}

		cg, err := cgroupByPID(pid)
		if err != nil || cg == "" {
			continue
		}
		identity := buildIdentity(namespace, podName, containerName)
		key := identity + "|" + cg
		if seen[key] {
			continue
		}
		seen[key] = true
		res = append(res, assoc{
			Identity:      identity,
			ContainerName: containerName,
			PodName:       podName,
			Namespace:     namespace,
			PID:           pid,
			Cgroup:        cg,
		})
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Identity != res[j].Identity {
			return res[i].Identity < res[j].Identity
		}
		return res[i].Cgroup < res[j].Cgroup
	})
	return res, nil
}

func inspectMetadata(id string) (int, map[string]string, error) {
	out, err := exec.Command("crictl", "inspect", "-o", "json", id).Output()
	if err != nil {
		return 0, nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		return 0, nil, err
	}

	labels := readLabels(raw)

	for _, p := range [][]string{{"info", "pid"}, {"status", "pid"}, {"pid"}} {
		if v, ok := lookup(raw, p...); ok {
			switch x := v.(type) {
			case float64:
				return int(x), labels, nil
			case string:
				n, _ := strconv.Atoi(x)
				if n > 0 {
					return n, labels, nil
				}
			}
		}
	}
	return 0, nil, errors.New("pid not found")
}

func readLabels(raw map[string]any) map[string]string {
	// Try common CRI inspect locations for labels across runtime versions.
	paths := [][]string{{"status", "labels"}, {"info", "config", "labels"}, {"labels"}}
	for _, p := range paths {
		if v, ok := lookup(raw, p...); ok {
			if m, ok := v.(map[string]any); ok {
				labels := map[string]string{}
				for k, val := range m {
					if s, ok := val.(string); ok {
						labels[k] = s
					}
				}
				return labels
			}
		}
	}
	return map[string]string{}
}

func buildIdentity(namespace, podName, containerName string) string {
	return namespace + "/" + podName + "/" + containerName
}

func splitIdentity(identity string) (string, string, string) {
	parts := strings.SplitN(identity, "/", 3)
	if len(parts) != 3 {
		return "unknown", "unknown", identity
	}
	return parts[0], parts[1], parts[2]
}

func cgroupByPID(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.SplitN(s.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return filepath.Join("/sys/fs/cgroup", strings.TrimSpace(parts[2])), nil
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no cgroup v2 entry")
}

func lookup(m map[string]any, path ...string) (any, bool) {
	cur := any(m)
	for _, p := range path {
		n, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = n[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func printMetrics(metrics map[flowKey]*metric) {
	type row struct {
		k flowKey
		v *metric
	}
	rows := make([]row, 0, len(metrics))
	for k, v := range metrics {
		rows = append(rows, row{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].k, rows[j].k
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.PodName != b.PodName {
			return a.PodName < b.PodName
		}
		if a.ContainerName != b.ContainerName {
			return a.ContainerName < b.ContainerName
		}
		if a.Dir != b.Dir {
			return a.Dir < b.Dir
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.SrcIP != b.SrcIP {
			return a.SrcIP < b.SrcIP
		}
		if a.SrcPort != b.SrcPort {
			return a.SrcPort < b.SrcPort
		}
		if a.DstIP != b.DstIP {
			return a.DstIP < b.DstIP
		}
		return a.DstPort < b.DstPort
	})

	fmt.Printf("\n# --- %s ---\n", time.Now().Format(time.RFC3339))
	fmt.Println("# HELP flow_packets_total packets observed by cgroup_skb")
	fmt.Println("# TYPE flow_packets_total counter")
	fmt.Println("# HELP flow_bytes_total bytes observed by cgroup_skb")
	fmt.Println("# TYPE flow_bytes_total counter")
	for _, r := range rows {
		k, v := r.k, r.v
		fmt.Printf("flow_packets_total{namespace=%q,pod=%q,container=%q,dir=%q,proto=%q,src_ip=%q,src_port=%q,dst_ip=%q,dst_port=%q} %d\n", k.Namespace, k.PodName, k.ContainerName, k.Dir, k.Proto, k.SrcIP, strconv.Itoa(int(k.SrcPort)), k.DstIP, strconv.Itoa(int(k.DstPort)), v.Packets)
		fmt.Printf("flow_bytes_total{namespace=%q,pod=%q,container=%q,dir=%q,proto=%q,src_ip=%q,src_port=%q,dst_ip=%q,dst_port=%q} %d\n", k.Namespace, k.PodName, k.ContainerName, k.Dir, k.Proto, k.SrcIP, strconv.Itoa(int(k.SrcPort)), k.DstIP, strconv.Itoa(int(k.DstPort)), v.Bytes)
	}
}

func proto(p uint8) string {
	switch p {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	default:
		return strconv.Itoa(int(p))
	}
}

func ip(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
