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
	__u8 tcp_flags;

	struct tuple t;

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

	if (iph->daddr == upstream_addr)
	{
		return TC_ACT_OK;
	}

	// only handle tcp
	if (iph->protocol != IPPROTO_TCP)
	{
		return TC_ACT_OK;
	}

	bpf_skb_load_bytes(skb, l4_off + TCP_SPORT_OFF, &sport, sizeof(__be16));
	bpf_skb_load_bytes(skb, l4_off + TCP_DPORT_OFF, &dport, sizeof(__be16));
	bpf_skb_load_bytes(skb, l4_off + 12, &tcp_flags, sizeof(__u8));

	magic = bpf_get_prandom_u32();

	res = set_opt(skb, iph, magic);
	if (res < 0)
	{
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
	struct iphdr *iph;
	struct ethhdr *ethh;
	__u32 magic;
	__u32 l4_off = ETH_HLEN + sizeof(*iph) + sizeof(struct msq_obsrv_opt);
	__be16 sport, dport;

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

	magic = get_opt(skb, iph);

	return TC_ACT_OK;
}
