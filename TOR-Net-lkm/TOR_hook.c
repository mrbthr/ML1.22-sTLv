#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/uidgid.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marbathara");
MODULE_DESCRIPTION("Linux Netfilter LKM for Bidirectional Transparent Tor DNAT");
MODULE_VERSION("0.2");


#define TOR_TRANS_PORT 9040
#define TOR_DNS_PORT   5353
#define LOOPBACK_IP    htonl(INADDR_LOOPBACK) /* 127.0.0.1 */


static unsigned int tor_uid = 123;
module_param(tor_uid, uint, 0644);
MODULE_PARM_DESC(tor_uid, "UID of the local Tor daemon user to exempt from redirection");

/

struct nat_entry {
    struct list_head list;
    __be16 sport;          /* Local ephemeral source port */
    __be32 orig_daddr;     /* Original remote destination IP */
    __be16 orig_dport;     /* Original remote destination port */
    u8 proto;              /* IPPROTO_TCP or IPPROTO_UDP */
};

static LIST_HEAD(nat_table);
static DEFINE_SPINLOCK(nat_lock);

static struct nf_hook_ops nfho_out;
static struct nf_hook_ops nfho_in;


static void nat_record_save(__be16 sport, __be32 daddr, __be16 dport, u8 proto)
{
    struct nat_entry *entry, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&nat_lock, flags);
    list_for_each_entry_safe(entry, tmp, &nat_table, list) {
        if (entry->sport == sport && entry->proto == proto) {
            entry->orig_daddr = daddr;
            entry->orig_dport = dport;
            spin_unlock_irqrestore(&nat_lock, flags);
            return;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (entry) {
        entry->sport = sport;
        entry->orig_daddr = daddr;
        entry->orig_dport = dport;
        entry->proto = proto;
        list_add(&entry->list, &nat_table);
    }
    spin_unlock_irqrestore(&nat_lock, flags);
}


static bool nat_record_lookup(__be16 dport, u8 proto, __be32 *orig_saddr, __be16 *orig_sport)
{
    struct nat_entry *entry;
    unsigned long flags;
    bool found = false;

    spin_lock_irqsave(&nat_lock, flags);
    list_for_each_entry(entry, &nat_table, list) {
        if (entry->sport == dport && entry->proto == proto) {
            *orig_saddr = entry->orig_daddr;
            *orig_sport = entry->orig_dport;
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&nat_lock, flags);
    return found;
}


static void update_tcp_checksums(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
{
    int tcplen = ntohs(iph->tot_len) - (iph->ihl * 4);

    iph->check = 0;
    ip_send_check(iph);

    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                    tcplen, IPPROTO_TCP,
                                    csum_partial((char *)tcph, tcplen, 0));
    skb->ip_summed = CHECKSUM_NONE;
}


static void update_udp_checksums(struct sk_buff *skb, struct iphdr *iph, struct udphdr *udph)
{
    int udplen = ntohs(iph->tot_len) - (iph->ihl * 4);

    iph->check = 0;
    ip_send_check(iph);

    udph->check = 0;
    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                    udplen, IPPROTO_UDP,
                                    csum_partial((char *)udph, udplen, 0));
    skb->ip_summed = CHECKSUM_NONE;
}


static unsigned int tor_out_hook(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    kuid_t sk_uid;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    
    if ((ntohl(iph->daddr) & 0xff000000) == 0x7f000000)
        return NF_ACCEPT;

    
    if (skb->sk) {
        sk_uid = sock_i_uid(skb->sk);
        if (uid_eq(sk_uid, make_kuid(&init_user_ns, tor_uid)))
            return NF_ACCEPT;
    }

    /* Handle TCP DNAT -> 127.0.0.1:TOR_TRANS_PORT */
    if (iph->protocol == IPPROTO_TCP) {
        if (skb_ensure_writable(skb, sizeof(struct iphdr) + sizeof(struct tcphdr)))
            return NF_DROP;

        iph = ip_hdr(skb);
        tcph = tcp_hdr(skb);

        nat_record_save(tcph->source, iph->daddr, tcph->dest, IPPROTO_TCP);

        iph->saddr = LOOPBACK_IP;
        iph->daddr = LOOPBACK_IP;
        tcph->dest = htons(TOR_TRANS_PORT);

        update_tcp_checksums(skb, iph, tcph);

        
        if (ip_route_me_harder(state->net, state->sk, skb, RTN_LOCAL) < 0)
            return NF_DROP;

        return NF_ACCEPT;
    }

    /* Handle UDP DNS DNAT -> 127.0.0.1:TOR_DNS_PORT */
    if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (!udph || ntohs(udph->dest) != 53)
            return NF_DROP; /* Block non-DNS UDP leaks (e.g., QUIC/WebRTC) */

        if (skb_ensure_writable(skb, sizeof(struct iphdr) + sizeof(struct udphdr)))
            return NF_DROP;

        iph = ip_hdr(skb);
        udph = udp_hdr(skb);

        nat_record_save(udph->source, iph->daddr, udph->dest, IPPROTO_UDP);

        iph->saddr = LOOPBACK_IP;
        iph->daddr = LOOPBACK_IP;
        udph->dest = htons(TOR_DNS_PORT);

        update_udp_checksums(skb, iph, udph);

        if (ip_route_me_harder(state->net, state->sk, skb, RTN_LOCAL) < 0)
            return NF_DROP;

        return NF_ACCEPT;
    }

    return NF_DROP; /* Drop raw ICMP/other protocols to prevent leaks */
}


static unsigned int tor_in_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    __be32 orig_saddr;
    __be16 orig_sport;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->saddr != LOOPBACK_IP || iph->daddr != LOOPBACK_IP)
        return NF_ACCEPT;

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (!tcph || ntohs(tcph->source) != TOR_TRANS_PORT)
            return NF_ACCEPT;

        if (nat_record_lookup(tcph->dest, IPPROTO_TCP, &orig_saddr, &orig_sport)) {
            if (skb_ensure_writable(skb, sizeof(struct iphdr) + sizeof(struct tcphdr)))
                return NF_DROP;

            iph = ip_hdr(skb);
            tcph = tcp_hdr(skb);

            iph->saddr = orig_saddr;
            tcph->source = orig_sport;

            update_tcp_checksums(skb, iph, tcph);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (!udph || ntohs(udph->source) != TOR_DNS_PORT)
            return NF_ACCEPT;

        if (nat_record_lookup(udph->dest, IPPROTO_UDP, &orig_saddr, &orig_sport)) {
            if (skb_ensure_writable(skb, sizeof(struct iphdr) + sizeof(struct udphdr)))
                return NF_DROP;

            iph = ip_hdr(skb);
            udph = udp_hdr(skb);

            iph->saddr = orig_saddr;
            udph->source = orig_sport;

            update_udp_checksums(skb, iph, udph);
        }
    }

    return NF_ACCEPT;
}

static int __init tor_hook_init(void)
{
    int ret;

    nfho_out.hook     = tor_out_hook;
    nfho_out.hooknum  = NF_INET_LOCAL_OUT;
    nfho_out.pf       = PF_INET;
    nfho_out.priority = NF_IP_PRI_NAT_DST;

    nfho_in.hook      = tor_in_hook;
    nfho_in.hooknum   = NF_INET_LOCAL_IN;
    nfho_in.pf        = PF_INET;
    nfho_in.priority  = NF_IP_PRI_NAT_SRC;

    ret = nf_register_net_hook(&init_net, &nfho_out);
    if (ret) {
        pr_err("tor_hook: Failed to register LOCAL_OUT hook\n");
        return ret;
    }

    ret = nf_register_net_hook(&init_net, &nfho_in);
    if (ret) {
        nf_unregister_net_hook(&init_net, &nfho_out);
        pr_err("tor_hook: Failed to register LOCAL_IN hook\n");
        return ret;
    }

    pr_info("tor_hook: Bidirectional DNAT loaded (exempt UID: %u)\n", tor_uid);
    return 0;
}

static void __exit tor_hook_exit(void)
{
    struct nat_entry *entry, *tmp;
    unsigned long flags;

    nf_unregister_net_hook(&init_net, &nfho_out);
    nf_unregister_net_hook(&init_net, &nfho_in);

    spin_lock_irqsave(&nat_lock, flags);
    list_for_each_entry_safe(entry, tmp, &nat_table, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&nat_lock, flags);

    pr_info("tor_hook: Unloaded and NAT state freed\n");
}

module_init(tor_hook_init);
module_exit(tor_hook_exit);
