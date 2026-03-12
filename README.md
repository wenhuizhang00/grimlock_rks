# grimlock_rks

Dynamic cgroup eBPF flow tracer in Go.

## What it does

- Discovers running containers with `crictl ps -o json`.
- Resolves each container PID via `crictl inspect -o json <id>`.
- Resolves each PID's cgroup (`/proc/<pid>/cgroup`, cgroup v2).
- Attaches `cgroup_skb/egress` eBPF programs to each discovered cgroup.
- Emits per-packet flow tuples (src/dst IP + ports, protocol, direction) into userspace.
- Aggregates and prints Prometheus-style counters labeled by Kubernetes `namespace`, `pod`, `container` and tuple.

## Build

```bash
go mod tidy
clang -O2 -g -target bpf -c bpf/flow.c -o bpf/flow.o
go build -o cgflow .
```

## Run

```bash
sudo ./cgflow
```

Requirements:

- Linux host with cgroup v2
- root privileges
- `crictl` configured for the node runtime
- clang/llvm + kernel headers + eBPF support
