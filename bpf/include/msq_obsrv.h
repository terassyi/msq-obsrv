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

struct event
{
	struct tuple t;
	__u32 dir;
	__u32 magic;
};

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct tuple);
	__uint(max_entries, BPF_MAP_MAX_CAPACITY);
} conntrack SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuple);
	__type(value, __u32);
	__uint(max_entries, BPF_MAP_MAX_CAPACITY);
} to_magic SEC(".maps");

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
