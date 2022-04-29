#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>

// #include "hyperion/ebpf/helpers.c"

typedef __be32 ip_addr;
typedef __be16 port;

BPF_HASH(disallowed_ports, port, int);
BPF_HASH(banned_ips, ip_addr, int);

__attribute__((__always_inline__))
    static inline int parse_packet(struct ethhdr * eth, void * data_end, __be32 ** saddr, __be32 ** daddr, __be16 ** sport, __be16 ** dport) {

        if(eth->h_proto != bpf_htons(ETH_P_IP)) {
            bpf_trace_printk("error#4");
            return 0;
        }

        struct iphdr *iph;
        iph = (struct iphdr *) (eth + 1);
        if((void *)(iph + 1) > data_end) {
            bpf_trace_printk("error#5");
            return -1;
        }

        // IP address
        (* saddr) = &iph->saddr;
        (* daddr) = &iph->daddr;

        // Invalid IP header or not supported
        if(iph->ihl != 5 || (iph->frag_off & 65343) || (iph->ttl <= 0)) {
            bpf_trace_printk("error#6");
            return 0;
        }

        if(iph->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *) (iph + 1);
            if((void *) (udp + 1) > data_end) {
            bpf_trace_printk("error#7");
                return -1;
            }
            (* sport) = &udp->source;
            (* dport) = &udp->dest;
        } else if(iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *) (iph + 1);
            if((void *) (tcp + 1) > data_end) {
                bpf_trace_printk("error#8");
                return -1;
            }
            (* sport) = &tcp->source;
            (* dport) = &tcp->dest;
        } else {
            return 0;
        }
        return 1;
    }

int hook(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    uint64_t nh_off;
    nh_off = sizeof(*eth);

    if((data + nh_off) > data_end) {
        bpf_trace_printk("error#1");
        return XDP_DROP;
    }

    ip_addr *saddr = NULL;
    ip_addr *daddr = NULL;
    port *sport = NULL;
    port *dport = NULL;
    int ret = parse_packet(eth, data_end, &saddr, &daddr, &sport, &dport);
    if(ret == 0) {
        bpf_trace_printk("error#2");
        return XDP_PASS;
    } else if(ret == -1) {
        bpf_trace_printk("error#3");
        return XDP_DROP;
    }
    // bpf_trace_printk("Packet recieve: (%d,%d,%d)\\n", bpf_ntohl(*saddr), bpf_ntohl(*daddr), bpf_ntohs(*dport));

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
