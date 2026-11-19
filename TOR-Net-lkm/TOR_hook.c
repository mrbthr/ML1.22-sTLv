#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Linux Netfilter LKM for Tor Traffic Inspection & Leak Prevention");
MODULE_VERSION("0.1");

#define TOR_TRANS_PORT 9040
#define TOR_DNS_PORT   5353
#define TOR_SOCKS_PORT 9050

static struct nf_hook_ops nfho;

/* Netfilter hook callback outgoing IPv4 packets */
static unsigned int tor_nf_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    /* Allow loopback traffic (127.0.0.0/8)  */
    if ((ntohl(iph->daddr) & 0xff000000) == 0x7f000000)
        return NF_ACCEPT;

    /* Inspect UDP packets: Block standard port 53 DNS leaks */
    if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (udph && ntohs(udph->dest) == 53) {
            pr_info("tor_hook: Dropped potential clearnet UDP DNS leak to %pI4\n", &iph->daddr);
            return NF_DROP;
        }
    }

    /* Inspect TCP packets: Log non-Tor outbound connections */
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (tcph) {
            u16 dport = ntohs(tcph->dest);
            if (dport != TOR_TRANS_PORT && dport != TOR_SOCKS_PORT) {
                /* Extend here with DNAT / skb rewriting or drop rules */
                pr_debug("tor_hook: Outbound TCP packet to %pI4:%u\n", &iph->daddr, dport);
            }
        }
    }

    return NF_ACCEPT;
}

static int __init tor_hook_init(void)
{
    nfho.hook     = tor_nf_hook;
    nfho.hooknum  = NF_INET_LOCAL_OUT;
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nfho)) {
        pr_err("tor_hook: Failed to register netfilter hook\n");
        return -1;
    }

    pr_info("tor_hook: Loaded successfully\n");
    return 0;
}

static void __exit tor_hook_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    pr_info("tor_hook: Unloaded\n");
}

module_init(tor_hook_init);
module_exit(tor_hook_exit);
