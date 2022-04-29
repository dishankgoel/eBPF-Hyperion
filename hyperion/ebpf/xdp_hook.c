#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#include "hyperion/ebpf/helpers.c"

typedef __be32 ip_addr;
typedef __be16 port;

BPF_HASH(disallowed_ports, port, int);
BPF_HASH(banned_ips, ip_addr, int);

int hook(struct xdp_md *ctx) {

    bpf_trace_printk("Got packet\\n");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    ip_addr *saddr = NULL;
    ip_addr *daddr = NULL;
    port *sport = NULL;
    port *dport = NULL;
    int ret = parse_packet(eth, data_end, &saddr, &daddr, &sport, &dport);
    if(ret == 0) {
        return XDP_PASS;
    } else if(ret == -1) {
        return XDP_DROP;
    }
    bpf_trace_printk("Packet recieve: (%d,%d,%d)\\n", *saddr, *daddr, *dport);

    // Check user policies
    // Check if port is allowed
    int *val = disallowed_ports.lookup(dport);
    if(val != NULL) {
        return XDP_DROP;
    }
    // Check if ip addr is allowed
    val = banned_ips.lookup(saddr);
    if(val != NULL) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
