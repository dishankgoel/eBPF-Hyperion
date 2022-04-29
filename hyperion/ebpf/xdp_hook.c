#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <stdlib.h>

#include "helpers.c"

typedef __be32 ip_addr;
typedef __be16 port;

BPF_HASH(disallowed_ports, __be16, int);

BPF_HASH(disallowed_protocols, int, int);

BPF_HASH(banned_ips, int, int);

int hook(struct xdp_md *ctx) {

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

    // Check user policies

}
