#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>

__attribute__((__always_inline__))
    static inline int parse_packet(struct ethhdr * eth, void * data_end, __be32 ** saddr, __be32 ** daddr, __be16 ** sport, __be16 ** dport) {

        if(eth->h_proto != bpf_htons(ETH_P_IP)) {
            bpf_trace_printk("error#4");
            return 0;
        }

        struct iphdr *iph;
        iph = (struct iphdr *) (eth + 1);
        if((void *)(iph + sizeof(*iph)) > data_end) {
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
