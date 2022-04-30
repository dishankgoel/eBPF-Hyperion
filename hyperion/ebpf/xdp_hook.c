#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>

// #include "hyperion/ebpf/helpers.c"

typedef __be32 ip_addr;
typedef long long mac_addr;
typedef __be16 port;

#define HYP_PORT 23479

BPF_HASH(disallowed_ports, port, int);
BPF_HASH(banned_ips, ip_addr, int);

BPF_ARRAY(nextcontainer, uint32_t, 1);

BPF_ARRAY(containers, ip_addr, 500);
BPF_ARRAY(containers_mac, mac_addr, 500);

// BPF_HISTOGRAM(tcp_counter, )

__attribute__((__always_inline__))
    static inline int parse_packet(struct ethhdr * eth, void * data_end, __be32 ** saddr, __be32 ** daddr, __be16 ** sport, __be16 ** dport, int * protocol) {

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
            (* protocol) = 0;
        } else if(iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *) (iph + 1);
            if((void *) (tcp + 1) > data_end) {
                bpf_trace_printk("error#8");
                return -1;
            }
            (* sport) = &tcp->source;
            (* dport) = &tcp->dest;
            (* protocol) = 1;
        } else {
            return 0;
        }
        return 1;
    }

// Checksum utilities
__attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
  int i;
  #pragma unroll
  for (i = 0; i < 4; i ++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

// Update checksum following RFC 1624 (Eqn. 3): https://tools.ietf.org/html/rfc1624
//     HC' = ~(~HC + ~m + m')
// Where :
//   HC  - old checksum in header
//   HC' - new checksum in header
//   m   - old value
//   m'  - new value
__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    // ~HC
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    // + m
    *csum += new_addr;
    // then fold and complement result !
    *csum = csum_fold_helper(*csum);
}


__attribute__((__always_inline__))
static inline void update_ip_checksum(struct ethhdr * eth, void * data_end, ip_addr old_addr, ip_addr new_addr) {
     struct iphdr *iph;
    iph = (struct iphdr *) (eth + 1);
    __u64 cs = iph->check;
    update_csum(&cs, old_addr, new_addr);
    iph->check = cs;
    return;
}

__attribute__((__always_inline__))
static inline int update_udp_checksum(__u64 cs, ip_addr old_addr, ip_addr new_addr) {
    update_csum(&cs , old_addr, new_addr);
    return cs;
}


/* static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
} */

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
    int protocol = 0;
    int ret = parse_packet(eth, data_end, &saddr, &daddr, &sport, &dport, &protocol);
    if(ret == 0) {
        bpf_trace_printk("error#2");
        return XDP_PASS;
    } else if(ret == -1) {
        bpf_trace_printk("error#3");
        return XDP_DROP;
    }
    bpf_trace_printk("Packet recieve: (%u,%u,%u)", bpf_ntohl(*saddr), bpf_ntohl(*daddr), bpf_ntohs(*dport));

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
    struct iphdr *iph;
    iph = (struct iphdr *) (eth + 1);


    ip_addr old_addr;
    __builtin_memset(&old_addr, 0, sizeof(old_addr));
    ip_addr new_addr;
    __builtin_memset(&new_addr, 0, sizeof(new_addr));



    // Ingress traffic
    if(*saddr == HOST_IP) {
        // This is our hyperion API, do not load balance it
        if(*dport == bpf_htons(HYP_PORT)) {
            return XDP_PASS;
        } else {
            // Handle the ingress traffic
            int zero = 0;
            uint32_t *nextserver = nextcontainer.lookup(&zero);
            ip_addr *new_dest = containers.lookup(nextserver);
            mac_addr *new_mac = containers_mac.lookup(nextserver);

            (old_addr) = (iph->daddr);
            (new_addr) = (* new_dest);

            iph->daddr = (* new_dest);
            eth->h_dest[5] = ((*new_mac) >> (40 - 8*5)) & 0xff;
            eth->h_dest[4] = ((*new_mac) >> (40 - 8*4)) & 0xff;
            eth->h_dest[3] = ((*new_mac) >> (40 - 8*3)) & 0xff;
            eth->h_dest[2] = ((*new_mac) >> (40 - 8*2)) & 0xff;
            eth->h_dest[1] = ((*new_mac) >> (40 - 8*1)) & 0xff;
            eth->h_dest[0] = ((*new_mac) >> (40 - 8*0)) & 0xff;
            // Update next server as LB target
            *nextserver = ((*nextserver) + 1) % NUM_CONTAINERS;
        }
    } else {
        if(*sport == bpf_htons(HYP_PORT)) {
            return XDP_PASS;
        } else {
            // egress traffic

            (old_addr) = (iph->daddr);
            (new_addr) = HOST_IP;

            iph->daddr = HOST_IP;
            eth->h_dest[5] = (HOST_MAC >> (40 - 8*5)) & 0xff;
            eth->h_dest[4] = (HOST_MAC >> (40 - 8*4)) & 0xff;
            eth->h_dest[3] = (HOST_MAC >> (40 - 8*3)) & 0xff;
            eth->h_dest[2] = (HOST_MAC >> (40 - 8*2)) & 0xff;
            eth->h_dest[1] = (HOST_MAC >> (40 - 8*1)) & 0xff;
            eth->h_dest[0] = (HOST_MAC >> (40 - 8*0)) & 0xff;
        }
    }

    iph->saddr = LB_IP;
    eth->h_source[5] = (LB_MAC >> (40 - 8*5)) & 0xff;
    eth->h_source[4] = (LB_MAC >> (40 - 8*4)) & 0xff;
    eth->h_source[3] = (LB_MAC >> (40 - 8*3)) & 0xff;
    eth->h_source[2] = (LB_MAC >> (40 - 8*2)) & 0xff;
    eth->h_source[1] = (LB_MAC >> (40 - 8*1)) & 0xff;
    eth->h_source[0] = (LB_MAC >> (40 - 8*0)) & 0xff;

    update_ip_checksum(eth, data_end, old_addr, new_addr);

    if(protocol == 0) { // Update UDP checksum
        struct udphdr *udp = (struct udphdr *) (iph + 1);
        udp->check = update_udp_checksum(udp->check, old_addr, new_addr);
    }

    return XDP_TX;
}
