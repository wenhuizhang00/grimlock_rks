#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 image_slot = 0;

struct flow_event {
    __u64 ts_ns;
    __u32 image_slot;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 pkt_len;
    __u8 proto;
    __u8 dir;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int trace_flow(struct __sk_buff *skb, __u8 dir)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return 1;

    if (iph->version != 4)
        return 1;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return 1;

    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph))
        return 1;

    if (data + ihl > data_end)
        return 1;

    __u16 sport = 0;
    __u16 dport = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + ihl;
        if ((void *)(tcph + 1) > data_end)
            return 1;
        sport = bpf_ntohs(tcph->source);
        dport = bpf_ntohs(tcph->dest);
    } else {
        struct udphdr *udph = data + ihl;
        if ((void *)(udph + 1) > data_end)
            return 1;
        sport = bpf_ntohs(udph->source);
        dport = bpf_ntohs(udph->dest);
    }

    struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 1;

    e->ts_ns = bpf_ktime_get_ns();
    e->image_slot = image_slot;
    e->saddr = iph->saddr;
    e->daddr = iph->daddr;
    e->sport = sport;
    e->dport = dport;
    e->pkt_len = skb->len;
    e->proto = iph->protocol;
    e->dir = dir;

    bpf_ringbuf_submit(e, 0);
    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb)
{
    return trace_flow(skb, 1);
}
