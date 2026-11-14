// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/qxdp_common.h"

volatile const __u64 CFG_KEY_EPOCH      = 0x9E3779B97F4A7C15ULL;
volatile const __u64 CFG_SIG_CENTROID_1 = 0x0ULL;
volatile const __u64 CFG_CARE_MASK_1    = 0x0ULL;
volatile const __u32 CFG_HAMMING_MAX_1  = 0;
volatile const __u64 CFG_SIG_CENTROID_2 = 0x0ULL;
volatile const __u64 CFG_CARE_MASK_2    = 0x0ULL;
volatile const __u32 CFG_HAMMING_MAX_2  = 0;
volatile const __u64 CFG_SIG_CENTROID_3 = 0x0ULL;
volatile const __u64 CFG_CARE_MASK_3    = 0x0ULL;
volatile const __u32 CFG_HAMMING_MAX_3  = 0;
volatile const __u64 CFG_SIG_CENTROID_4 = 0x0ULL;
volatile const __u64 CFG_CARE_MASK_4    = 0x0ULL;
volatile const __u32 CFG_HAMMING_MAX_4  = 0;
volatile const __u64 CFG_SIG_CENTROID_5 = 0x0ULL;
volatile const __u64 CFG_CARE_MASK_5    = 0x0ULL;
volatile const __u32 CFG_HAMMING_MAX_5  = 0;
volatile const __u64 CFG_SIG_CENTROID_6 = 0x0ULL;
volatile const __u64 CFG_CARE_MASK_6    = 0x0ULL;
volatile const __u32 CFG_HAMMING_MAX_6  = 0;
volatile const __u64 CFG_SIG_CENTROID_7 = 0x0ULL;
volatile const __u64 CFG_CARE_MASK_7    = 0x0ULL;
volatile const __u32 CFG_HAMMING_MAX_7  = 0;
volatile const __u64 CFG_SIG_CENTROID_8 = 0x0ULL;
volatile const __u64 CFG_CARE_MASK_8    = 0x0ULL;
volatile const __u32 CFG_HAMMING_MAX_8  = 0;
volatile const __u32 CFG_ENABLE_TAP     = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct qxdp_sketch_state);
	__uint(max_entries, 1);
} sketch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} tap_ringbuf SEC(".maps");

static __always_inline void sketch_update(struct qxdp_sketch_state *s,
					  __u64 q_pkt, __u32 src_ip)
{
	__u64 h = fasthash64(q_pkt, CFG_KEY_EPOCH);

	#pragma unroll
	for (int r = 0; r < SKETCH_HDR_ROWS; r++) {
		__u32 idx = (h >> (r * 16)) & (SKETCH_HDR_COLS - 1);
		s->view_a_hdr[r][idx & (SKETCH_HDR_COLS - 1)]++;
	}

	__u64 h2 = fasthash64(q_pkt ^ 0xDEADBEEFCAFEBABEULL, CFG_KEY_EPOCH);

	#pragma unroll
	for (int r = 0; r < SKETCH_PL_ROWS; r++) {
		__u32 idx = (h2 >> (r * 16)) & (SKETCH_PL_COLS - 1);
		{
			struct hk_bucket *b = &s->view_b_payload[r][idx];
			if (b->fingerprint == q_pkt) {
				b->count++;
				b->src_ip_sample = src_ip;
			} else {
				__u32 cursor = s->prng_cursor;
				__u32 rnd = s->prng_ring[cursor & (PRNG_RING_SIZE - 1)];
				s->prng_cursor = cursor + 1;
				__u32 decay = (rnd & 0xFFFF) % (b->count + 1);
				if (decay == 0) {
					b->fingerprint = q_pkt;
					b->count = 1;
					b->src_ip_sample = src_ip;
					s->sketch_collisions++;
				} else {
					b->count--;
				}
			}
		}
	}
}

SEC("xdp")
int qxdp_aegis(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 src_ip;
	__u64 q_pkt = quantize_packet(data, data_end, CFG_KEY_EPOCH, &src_ip);
	if (q_pkt == 0)
		return XDP_PASS;

	/* --- Zero-lookup fast path: signature checks BEFORE any map access --- */
	if (CFG_CARE_MASK_1 != 0) {
		__u64 diff = (q_pkt ^ CFG_SIG_CENTROID_1) & CFG_CARE_MASK_1;
		__u32 dist = swar_popcount64(diff);
		if (dist <= CFG_HAMMING_MAX_1) {
			if (CFG_ENABLE_TAP == 1) {
				__u32 key = 0;
				struct qxdp_sketch_state *s = bpf_map_lookup_elem(&sketch_map, &key);
				if (s) {
					s->drop_pkts++;
					s->drop_bytes += (__u64)(data_end - data);
				}
				struct tap_event *ev = bpf_ringbuf_reserve(&tap_ringbuf,
					sizeof(struct tap_event), 0);
				if (ev) {
					ev->timestamp_ns = bpf_ktime_get_ns();
					ev->q_token = q_pkt;
					ev->action = 1;
					ev->pkt_len = (__u32)(data_end - data);
					if ((void *)data + TAP_FRAME_SIZE <= data_end)
						bpf_probe_read_kernel(ev->raw_frame, TAP_FRAME_SIZE, data);
					bpf_ringbuf_submit(ev, 0);
				}
			}
			return XDP_DROP;
		}
	}

	#define CHECK_SIG(N) do { \
		if (CFG_CARE_MASK_##N != 0) { \
			__u64 diff##N = (q_pkt ^ CFG_SIG_CENTROID_##N) & CFG_CARE_MASK_##N; \
			if (swar_popcount64(diff##N) <= CFG_HAMMING_MAX_##N) \
				return XDP_DROP; \
		} \
	} while (0)

	CHECK_SIG(2);
	CHECK_SIG(3);
	CHECK_SIG(4);
	CHECK_SIG(5);
	CHECK_SIG(6);
	CHECK_SIG(7);
	CHECK_SIG(8);

	#undef CHECK_SIG

	/* slow path: sketch update requires map lookup */
	__u32 key = 0;
	struct qxdp_sketch_state *s = bpf_map_lookup_elem(&sketch_map, &key);
	if (s) {
		sketch_update(s, q_pkt, src_ip);
		s->pass_pkts++;
		s->pass_bytes += (__u64)(data_end - data);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
