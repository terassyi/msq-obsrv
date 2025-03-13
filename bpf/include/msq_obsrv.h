// #include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// #include <linux/ip.h>
// #include <net/ethernet.h>

#include "vmlinux.h"

#define ETH_HLEN 14 /* Total octets in header.	 */
#define ETH_P_IP 0x08
#define MAX_IPOPTLEN 40
#define IPOPT_COPY 0x80
#define MSQ_OBSRV_OPT_TYPE (IPOPT_COPY | 0x2a)

#define BPF_MAP_MAX_CAPACITY 1024 * 1024

struct msq_obsrv_opt
{
	__u8 type;
	__u8 len;
	__u16 pad;
	__u32 magic;
};

struct tuple
{
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 protocol;
};

struct tcp_stats
{
	__u8 syn_sent;
	__u8 syn_recv;
	__u8 fin_sent;
	__u8 fin_recv;
	__u8 rst_sent;
	__u8 rst_recv;
	__u16 ack_sent;
};

struct tcp_flag
{
	__u8 fin : 1; // 1
	__u8 syn : 1; // 1 << 1
	__u8 rst : 1; // 1 << 2
	__u8 psh : 1; // 1 << 3
	__u8 ack : 1; // 1 << 4
	__u8 urg : 1; // 1 << 5
	__u8 ece : 1; // 1 << 6
	__u8 cwr : 1; // 1 << 7
};

union tcp_flag_v {
	struct tcp_flag flag;
	__u8 v;
};

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuple);
	__type(value, struct tcp_stats);
	__uint(max_entries, BPF_MAP_MAX_CAPACITY);
} flow_stats SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BPF_MAP_MAX_CAPACITY);
} inv_sip SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct inv_sip_event);
	__type(value, u32);
	__uint(max_entries, 1);
} dummy_inv_sip SEC(".maps");

struct inv_sip_event
{
	struct tuple t;
	__u32 inv_sip;
	// struct tcp_flag flag;
	__u8 flag;
	__u16 pad1;
	__u8 pad2;
};

#ifndef BPF_FUNC_REMAP
#define BPF_FUNC_REMAP(NAME, ...) \
	(*NAME)(__VA_ARGS__)
#endif

static int
BPF_FUNC_REMAP(csum_diff_external, const void *from, __u32 size_from,
			   const void *to, __u32 size_to, __u32 seed) =
	(void *)BPF_FUNC_csum_diff;

static __always_inline int ipv4_hdrlen(const struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

// dir=true => sent
// dir=false => recv
static __always_inline void set_tcp_stats(struct tcp_flag flag, struct tcp_stats *stats, bool dir)
{
	if (dir)
	{
		if (flag.fin)
			stats->fin_sent++;
		else if (flag.syn)
			stats->syn_sent++;
		else if (flag.rst)
			stats->rst_sent++;
		else if (flag.ack)
			stats->ack_sent++;
	}
	else
	{
		if (flag.fin)
			stats->fin_recv++;
		else if (flag.syn)
			stats->syn_recv++;
		else if (flag.rst)
			stats->rst_recv++;
	}
}

static __always_inline __wsum csum_add(__wsum csum, __wsum addend)
{
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

static __always_inline __wsum csum_diff(const void *from, __u32 size_from,
										const void *to, __u32 size_to,
										__u32 seed)
{
	return csum_diff_external(from, size_from, to, size_to, seed);
}

static __always_inline int set_opt(struct __sk_buff *skb, struct iphdr *iphdr, __u32 magic)
{
	struct msq_obsrv_opt opt;
	__u32 dummy_opt;
	__u32 iph_old, iph_new;
	__u16 tot_len = bpf_ntohs(iphdr->tot_len) + sizeof(opt);
	__u32 sum = 0;

	if (ipv4_hdrlen(iphdr) + sizeof(opt) > sizeof(struct iphdr) + MAX_IPOPTLEN)
	{
		return -1;
	}

	iph_old = *(__u32 *)iphdr;

	iphdr->ihl += sizeof(opt) >> 2;
	iphdr->tot_len = bpf_htons(tot_len);
	iph_new = *(__u32 *)iphdr;

	dummy_opt = *(__u32 *)&opt;

	opt.type = MSQ_OBSRV_OPT_TYPE;
	opt.len = sizeof(opt);
	opt.magic = magic;

	sum = csum_diff(&iph_old, 4, &iph_new, 4, 0);
	sum = csum_diff(NULL, 0, &opt, sizeof(opt), sum);

	if (bpf_skb_adjust_room(skb, sizeof(opt), BPF_ADJ_ROOM_NET, 0))
	{
		return -2;
	}
	if (bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(*iphdr), &opt, sizeof(opt), 0) < 0)
	{
		return -3;
	}
	if (bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), 0, sum, 0) < 0)
	{
		return -4;
	}

	return 0;
}

static __always_inline __u32 get_opt(struct __sk_buff *skb, struct iphdr *iphdr)
{
	struct msq_obsrv_opt opt;

	if (iphdr->ihl < 0x7)
	{
		return 0;
	}

	if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &opt, sizeof(opt)) < 0)
	{
		return -1;
	}

	if (opt.type == MSQ_OBSRV_OPT_TYPE && opt.len == sizeof(opt))
	{
		return opt.magic;
	}

	return 0;
}
