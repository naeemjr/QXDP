// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/qxdp_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} morph_counter SEC(".maps");

SEC("xdp")
int qxdp_morph(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if ((void *)data + 90 > data_end)
		return XDP_PASS;

	struct ethhdr_min *eth = data;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr_min *iph = (void *)(eth + 1);
	__u8 proto = iph->protocol;

	__u32 key = 0;
	__u64 *ctr = bpf_map_lookup_elem(&morph_counter, &key);
	if (!ctr)
		return XDP_PASS;

	__u64 cnt = *ctr;
	*ctr = cnt + 1;

	/* rotate TTL low bits based on counter */
	iph->ttl = (iph->ttl & 0xC0) | ((__u8)(cnt & 0x3F));

	if (proto == IPPROTO_TCP) {
		struct tcphdr_min *tcp = (void *)(iph + 1);

		/* rotate TCP window */
		__u16 base_win = bswap16(tcp->window);
		__u16 new_win = base_win + (__u16)(cnt & 0xFF);
		tcp->window = bswap16(new_win);

		/* checksum-neutral complementary nibble perturbation on payload */
		__u8 doff = (bswap16(tcp->flags_doff) >> 12) & 0xF;
		__u32 tcp_hdr_len = (__u32)doff * 4;
		if (tcp_hdr_len < 20) tcp_hdr_len = 20;

		void *payload = (void *)tcp + tcp_hdr_len;
		/* perturb two adjacent 16-bit words at offset 8 */
		if (payload + 12 <= data_end) {
			__u8 *pl = payload;
			__u16 delta = (__u16)((cnt >> 8) & 0xFF);
			if (delta == 0) delta = 1;

			/* read word pair at offset 8 */
			__u16 w0 = ((__u16)pl[8] << 8) | pl[9];
			__u16 w1 = ((__u16)pl[10] << 8) | pl[11];

			/* ones-complement add/sub */
			__u32 sum0 = (__u32)w0 + (__u32)delta;
			w0 = (__u16)(sum0 + (sum0 >> 16));
			__u32 sum1 = (__u32)w1 - (__u32)delta;
			if (w1 < delta)
				sum1 = (__u32)((__u32)w1 + 0xFFFF - (__u32)delta);
			w1 = (__u16)(sum1 + (sum1 >> 16));

			pl[8]  = (__u8)(w0 >> 8);
			pl[9]  = (__u8)(w0 & 0xFF);
			pl[10] = (__u8)(w1 >> 8);
			pl[11] = (__u8)(w1 & 0xFF);
		}
	} else if (proto == IPPROTO_UDP) {
		struct udphdr_min *udp = (void *)(iph + 1);

		void *payload = (void *)udp + 8;
		if (payload + 12 <= data_end) {
			__u8 *pl = payload;
			__u16 delta = (__u16)((cnt >> 8) & 0xFF);
			if (delta == 0) delta = 1;

			__u16 w0 = ((__u16)pl[8] << 8) | pl[9];
			__u16 w1 = ((__u16)pl[10] << 8) | pl[11];

			__u32 sum0 = (__u32)w0 + (__u32)delta;
			w0 = (__u16)(sum0 + (sum0 >> 16));
			__u32 sum1 = (__u32)w1 - (__u32)delta;
			if (w1 < delta)
				sum1 = (__u32)((__u32)w1 + 0xFFFF - (__u32)delta);
			w1 = (__u16)(sum1 + (sum1 >> 16));

			pl[8]  = (__u8)(w0 >> 8);
			pl[9]  = (__u8)(w0 & 0xFF);
			pl[10] = (__u8)(w1 >> 8);
			pl[11] = (__u8)(w1 & 0xFF);
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
