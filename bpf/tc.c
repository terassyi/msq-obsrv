#include "vmlinux.h"
// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// #include <linux/pkt_cls.h>

#include "msq_obsrv.h"

#define TC_ACT_OK 0
#define TCP_DPORT_OFF (offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF (offsetof(struct tcphdr, source))

char __license[] SEC("license") = "Dual MIT/GPL";

__u32 upstream_addr = 0;

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{

	struct iphdr *iph;
	struct ethhdr *ethh;
	struct tcphdr *tcph;

	__u32 res;
	__u32 magic;
	__u32 l4_off = ETH_HLEN + sizeof(*iph);
	__be16 sport, dport;
	union tcp_flag_v tcp_flags;

	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;

	if (skb->protocol != ETH_P_IP)
	{
		return TC_ACT_OK;
	}

	ethh = data;
	if ((void *)(ethh + 1) > data_end)
		return TC_ACT_OK;

	iph = (struct iphdr *)(ethh + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;

	// only handle tcp
	if (iph->protocol != IPPROTO_TCP)
	{
		return TC_ACT_OK;
	}

	bpf_skb_load_bytes(skb, l4_off + TCP_SPORT_OFF, &sport, sizeof(__be16));
	bpf_skb_load_bytes(skb, l4_off + TCP_DPORT_OFF, &dport, sizeof(__be16));
	bpf_skb_load_bytes(skb, l4_off + 12, &tcp_flags, sizeof(__u8));

	// if (iph->daddr == upstream_addr)
	// {
	// 	bpf_printk("ingress: sport=%d, dir=reply", bpf_ntohs(sport));
	// 	bpf_printk("ingress: dport=%d, dir=reply", bpf_ntohs(dport));
	// }
	// else
	// {
	// 	bpf_printk("ingress: sport=%d, dir=orig", bpf_ntohs(sport));
	// 	bpf_printk("ingress: dport=%d, dir=orig", bpf_ntohs(dport));
	// }
	bpf_skb_load_bytes(skb, l4_off + 13, &tcp_flags, 1);

	struct tuple t = {
		// should I convert byte order?
		.daddr = iph->saddr,
		.saddr = iph->daddr,
		.dport = bpf_ntohs(sport),
		.sport = bpf_ntohs(dport),
		.protocol = IPPROTO_TCP,
	};

	void *r = bpf_map_lookup_elem(&flow_stats, &t);
	if (!r)
	{
		struct tcp_stats stat = {};
		set_tcp_stats(tcp_flags.flag, &stat, false);
		bpf_map_update_elem(&flow_stats, &t, &stat, 0);
	}
	else
	{
		struct tcp_stats *stat;
		stat = (struct tcp_stats *)r;
		set_tcp_stats(tcp_flags.flag, stat, false);
		bpf_map_update_elem(&flow_stats, &t, stat, 0);
	}

	// magic = bpf_get_prandom_u32();

	// res = set_opt(skb, iph, magic);
	// if (res < 0)
	// {
	// 	return TC_ACT_OK;
	// }

	return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
	struct iphdr *iph;
	struct ethhdr *ethh;
	__u32 magic;
	// __u32 l4_off = ETH_HLEN + sizeof(*iph) + sizeof(struct msq_obsrv_opt);
	__u32 l4_off = ETH_HLEN + sizeof(*iph);
	__be16 sport, dport;
	union tcp_flag_v tcp_flags;

	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;

	if (skb->protocol != ETH_P_IP)
	{
		return TC_ACT_OK;
	}

	ethh = data;
	if ((void *)(ethh + 1) > data_end)
		return TC_ACT_OK;

	iph = (struct iphdr *)(ethh + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;

	// only handle tcp
	if (iph->protocol != IPPROTO_TCP)
	{
		return TC_ACT_OK;
	}

	bpf_skb_load_bytes(skb, l4_off + TCP_SPORT_OFF, &sport, sizeof(__be16));
	bpf_skb_load_bytes(skb, l4_off + TCP_DPORT_OFF, &dport, sizeof(__be16));

	bpf_skb_load_bytes(skb, l4_off + 13, &tcp_flags, 1);


	struct tuple t = {
		// should I convert byte order?
		.saddr = iph->saddr,
		.daddr = iph->daddr,
		.sport = bpf_ntohs(sport),
		.dport = bpf_ntohs(dport),
		.protocol = IPPROTO_TCP,
	};

	if (upstream_addr != iph->saddr)
	// if (upstream_addr == iph->saddr)
	{
		// invalid source ip
		struct inv_sip_event *event;
		event = bpf_ringbuf_reserve(&inv_sip, sizeof(struct inv_sip_event), 0);
		if (!event) {
			return TC_ACT_OK;
		}
		event->inv_sip = t.saddr;
		event->t = t;
		event->flag = tcp_flags.v;

		bpf_ringbuf_submit(event, 0);

		t.saddr = upstream_addr;
	}

	void *res = bpf_map_lookup_elem(&flow_stats, &t);
	if (!res)
	{
		struct tcp_stats stat = {};
		set_tcp_stats(tcp_flags.flag, &stat, true);
		bpf_map_update_elem(&flow_stats, &t, &stat, 0);
	}
	else
	{
		struct tcp_stats *stat;
		stat = (struct tcp_stats *)res;
		set_tcp_stats(tcp_flags.flag, stat, true);
		bpf_map_update_elem(&flow_stats, &t, stat, 0);
	}

	// magic = get_opt(skb, iph);

	return TC_ACT_OK;
}
