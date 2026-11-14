#ifndef __QXDP_COMMON_H
#define __QXDP_COMMON_H

#include <linux/types.h>

#define ETH_HLEN      14
#define ETH_P_IP      0x0800
#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define IPPROTO_TCP   6
#define IPPROTO_UDP   17
#define IPPROTO_ICMP  1

#define SKETCH_HDR_ROWS   4
#define SKETCH_HDR_COLS   128
#define SKETCH_PL_ROWS    4
#define SKETCH_PL_COLS    256
#define PRNG_RING_SIZE    256

#define PAYLOAD_WINDOW    48
#define SHINGLE_STEPS     16
#define SHINGLE_STRIDE    2
#define TAP_FRAME_SIZE    128

struct ethhdr_min {
	__u8  h_dest[6];
	__u8  h_source[6];
	__be16 h_proto;
} __attribute__((packed));

struct iphdr_min {
	__u8  ihl_ver;
	__u8  tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8  ttl;
	__u8  protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed));

struct tcphdr_min {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16  flags_doff;
	__be16 window;
	__be16 check;
	__be16 urg_ptr;
} __attribute__((packed));

struct udphdr_min {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
} __attribute__((packed));

struct hk_bucket {
	__u64 fingerprint;
	__u32 count;
	__u32 src_ip_sample;
};

struct qxdp_sketch_state {
	__u32 view_a_hdr[SKETCH_HDR_ROWS][SKETCH_HDR_COLS];
	struct hk_bucket view_b_payload[SKETCH_PL_ROWS][SKETCH_PL_COLS];
	__u32 prng_ring[PRNG_RING_SIZE];
	__u32 prng_cursor;
	__u64 pass_pkts;
	__u64 drop_pkts;
	__u64 pass_bytes;
	__u64 drop_bytes;
	__u64 sketch_collisions;
};

struct tap_event {
	__u64 timestamp_ns;
	__u64 q_token;
	__u32 action;
	__u32 pkt_len;
	__u8  raw_frame[TAP_FRAME_SIZE];
};

static __always_inline __u32 swar_popcount64(__u64 x)
{
	x -= (x >> 1) & 0x5555555555555555ULL;
	x  = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
	x  = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
	return (__u32)((x * 0x0101010101010101ULL) >> 56);
}

static __always_inline __u64 fasthash64_mix(__u64 h)
{
	h ^= h >> 23;
	h *= 0x2127599BF4325C37ULL;
	h ^= h >> 47;
	return h;
}

static __always_inline __u64 fasthash64(__u64 val, __u64 seed)
{
	__u64 h = seed ^ (8ULL * 0x880355F21E6D1965ULL);
	h ^= fasthash64_mix(val);
	h *= 0x880355F21E6D1965ULL;
	return fasthash64_mix(h);
}

static __always_inline __u16 bswap16(__u16 x)
{
	return (x >> 8) | (x << 8);
}

static __always_inline __u32 bswap32(__u32 x)
{
	return ((x & 0xFF000000U) >> 24) |
	       ((x & 0x00FF0000U) >> 8)  |
	       ((x & 0x0000FF00U) << 8)  |
	       ((x & 0x000000FFU) << 24);
}

/*
 * Stage 2: Shift-invariant payload quantization (lower 48 bits).
 *
 * Bits 32..47: Protocol Header Offset Anchor — keyed hash of the first
 *              16 bytes of L4 payload (covers fixed-offset protocol fields
 *              like DNS ID, TLS record type, etc.).
 *
 * Bits  0..31: Sliding Shingle Bloom — 16 overlapping 4-byte shingles at
 *              2-byte stride (bytes 8..41) hashed into a 32-bit bloom.
 *              Content-addressed, not position-addressed, so a 2/4/6-byte
 *              payload prepend produces the same bloom.
 */
static __always_inline __u64 quantize_payload_lsh(void *pl_start, void *data_end,
						  __u64 key_epoch)
{
	if ((void *)pl_start + PAYLOAD_WINDOW > data_end)
		return 0;

	__u8 *pl = pl_start;
	__u64 lsh = 0;

	/* Bits 32..47: Anchor — first two 8-byte words → 16 bits */
	__u64 w0 = ((__u64)pl[0]  << 56) | ((__u64)pl[1]  << 48) |
		   ((__u64)pl[2]  << 40) | ((__u64)pl[3]  << 32) |
		   ((__u64)pl[4]  << 24) | ((__u64)pl[5]  << 16) |
		   ((__u64)pl[6]  << 8)  | ((__u64)pl[7]);
	__u64 w1 = ((__u64)pl[8]  << 56) | ((__u64)pl[9]  << 48) |
		   ((__u64)pl[10] << 40) | ((__u64)pl[11] << 32) |
		   ((__u64)pl[12] << 24) | ((__u64)pl[13] << 16) |
		   ((__u64)pl[14] << 8)  | ((__u64)pl[15]);
	__u64 ah = fasthash64(w0, key_epoch) ^ fasthash64(w1, key_epoch + 1);
	lsh |= ((__u64)(ah & 0xFFFF)) << 32;

	/* Bits 0..31: Sliding shingle bloom (bytes 8..41, stride 2, window 4) */
	__u32 sbl = 0;
	#pragma unroll
	for (int i = 0; i < SHINGLE_STEPS; i++) {
		__u32 off = 8 + i * SHINGLE_STRIDE;
		__u32 w = ((__u32)pl[off]   << 24) |
			  ((__u32)pl[off+1] << 16) |
			  ((__u32)pl[off+2] << 8)  |
			  ((__u32)pl[off+3]);
		__u32 h = (w ^ (__u32)key_epoch) * 0x9E3779B1U;
		h ^= h >> 16;
		sbl |= (1U << ((h >> 27) & 31));
	}
	lsh |= (__u64)sbl;

	return lsh & 0xFFFFFFFFFFFFULL;
}

/*
 * Two-stage packet quantization with VLAN stripping and dynamic IHL.
 *
 * Stage 1 (always): Parse L2→L3→L4 headers, produce upper 16-bit INT4
 *                   header token (bits 48..63). Works on every valid IPv4
 *                   TCP/UDP/ICMP frame — including 54-to-64 byte SYN floods.
 *
 * Stage 2 (conditional): If >= 48 bytes of L4 payload exist, compute lower
 *                        48-bit shift-invariant payload signature.
 *                        Otherwise bits 0..47 = 0.
 */
static __always_inline __u64 quantize_packet(void *data, void *data_end,
					     __u64 key_epoch, __u32 *out_src_ip)
{
	*out_src_ip = 0;

	/* ---- L2: Ethernet + optional VLAN ---- */
	struct ethhdr_min *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;

	__u16 eth_proto = eth->h_proto;
	void *l3 = (void *)(eth + 1);

	/* Strip up to 2 stacked 802.1Q / 802.1ad VLAN tags */
	#pragma unroll
	for (int v = 0; v < 2; v++) {
		if (eth_proto == bswap16(ETH_P_8021Q) ||
		    eth_proto == bswap16(ETH_P_8021AD)) {
			if ((void *)l3 + 4 > data_end)
				return 0;
			eth_proto = *(__u16 *)((void *)l3 + 2);
			l3 = (void *)l3 + 4;
		}
	}

	if (eth_proto != bswap16(ETH_P_IP))
		return 0;

	/* ---- L3: IPv4 with dynamic IHL ---- */
	struct iphdr_min *iph = l3;
	if ((void *)(iph + 1) > data_end)
		return 0;

	__u8 ihl = iph->ihl_ver & 0xF;
	if (ihl < 5)
		return 0;
	__u32 ihl_bytes = (__u32)ihl * 4;
	if (ihl_bytes > 60)
		ihl_bytes = 60;
	if ((void *)l3 + ihl_bytes > data_end)
		return 0;

	__u8 proto = iph->protocol;
	*out_src_ip = iph->saddr;

	void *l4 = (void *)l3 + ihl_bytes;
	__u64 q = 0;
	__u32 l4_payload_len = 0;
	__u32 l4_hdr_len = 0;

	/* ---- L4: TCP / UDP / ICMP ---- */
	if (proto == IPPROTO_TCP) {
		if ((void *)l4 + 20 > data_end)
			return 0;
		struct tcphdr_min *tcp = l4;

		/* Nibble 3 (bits 60..63): log2(window) */
		__u16 win = bswap16(tcp->window);
		__u8 log_win = 0;
		if (win > 0) {
			#pragma unroll
			for (int i = 0; i < 16; i++) {
				if (win >> i)
					log_win = i;
			}
		}
		q |= ((__u64)(log_win & 0xF)) << 60;

		/* Nibble 1 (bits 52..55): TCP flag state */
		__u16 raw = bswap16(tcp->flags_doff);
		__u8 flags = raw & 0x3F;
		__u8 syn = (flags >> 1) & 1;
		__u8 rst = (flags >> 2) & 1;
		__u8 ack = (flags >> 4) & 1;
		__u8 fin = flags & 1;
		q |= ((__u64)(((rst << 3) | (syn << 2) | (ack << 1) | fin) & 0xF)) << 52;

		/* TCP header length */
		__u8 doff = (raw >> 12) & 0xF;
		l4_hdr_len = (__u32)doff * 4;
		if (l4_hdr_len < 20) l4_hdr_len = 20;
		if (l4_hdr_len > 60) l4_hdr_len = 60;

		__u16 ip_total = bswap16(iph->tot_len);
		__u32 hdr_total = ihl_bytes + l4_hdr_len;
		if (ip_total > hdr_total)
			l4_payload_len = ip_total - hdr_total;

	} else if (proto == IPPROTO_UDP) {
		if ((void *)l4 + 8 > data_end)
			return 0;
		struct udphdr_min *udp = l4;

		__u16 ulen = bswap16(udp->len);
		__u8 bucket = 0;
		if (ulen >= 1024) bucket = 15;
		else if (ulen >= 512) bucket = 12;
		else if (ulen >= 256) bucket = 9;
		else if (ulen >= 128) bucket = 6;
		else if (ulen >= 64) bucket = 3;
		else bucket = 1;
		q |= ((__u64)(bucket & 0xF)) << 60;
		q |= ((__u64)1) << 52;

		l4_hdr_len = 8;
		if (ulen > 8)
			l4_payload_len = ulen - 8;

	} else if (proto == IPPROTO_ICMP) {
		if ((void *)l4 + 8 > data_end)
			return 0;
		q |= ((__u64)2) << 52;
		l4_hdr_len = 8;
	} else {
		return 0;
	}

	/* Nibble 2 (bits 56..59): TTL hop residual + frag flags */
	{
		__u8 ttl_q = (iph->ttl & 0x3F) >> 2;
		__u16 foff = bswap16(iph->frag_off);
		__u8 df = (foff >> 14) & 1;
		__u8 mf = (foff >> 13) & 1;
		__u8 nib = (ttl_q & 0xC) | (df << 1) | mf;
		q |= ((__u64)(nib & 0xF)) << 56;
	}

	/* Nibble 0 (bits 48..51): payload length bucket (/32) */
	{
		__u32 bucket = l4_payload_len / 32;
		if (bucket > 15) bucket = 15;
		q |= ((__u64)(bucket & 0xF)) << 48;
	}

	/* ---- Stage 2: Lower 48-bit payload quantizer (conditional) ---- */
	void *payload = (void *)l4 + l4_hdr_len;
	q |= quantize_payload_lsh(payload, data_end, key_epoch);

	return q;
}

#endif /* __QXDP_COMMON_H */
