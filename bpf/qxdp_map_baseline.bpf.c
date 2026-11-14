// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/qxdp_common.h"

volatile const __u64 CFG_KEY_EPOCH = 0x9E3779B97F4A7C15ULL;

struct sig_rule {
	__u64 centroid;
	__u64 care_mask;
	__u32 hamming_max;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct sig_rule);
	__uint(max_entries, 16);
} sig_map SEC(".maps");

SEC("xdp")
int qxdp_map_baseline(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 src_ip;
	__u64 q_pkt = quantize_packet(data, data_end, CFG_KEY_EPOCH, &src_ip);
	if (q_pkt == 0)
		return XDP_PASS;

	#pragma unroll
	for (int i = 0; i < 16; i++) {
		__u32 idx = i;
		struct sig_rule *rule = bpf_map_lookup_elem(&sig_map, &idx);
		if (!rule || rule->care_mask == 0)
			continue;
		__u64 diff = (q_pkt ^ rule->centroid) & rule->care_mask;
		__u32 dist = swar_popcount64(diff);
		if (dist <= rule->hamming_max)
			return XDP_DROP;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
