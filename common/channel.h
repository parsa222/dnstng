#pragma once
#include <stdint.h>
#include <stddef.h>
#include "dns_packet.h"
#include "util.h"

#define CHANNEL_MAX_ANSWERS 16
#define CHANNEL_MAX_NS       8
#define CHANNEL_RDATA_CAP   8192

/*
 * channel_buf_t: working buffer for channel_pack / channel_unpack.
 * Initialize with channel_buf_init() before use.
 */
typedef struct {
    dns_answer_t  answers[CHANNEL_MAX_ANSWERS];
    size_t        num_answers;
    char          ns_names[CHANNEL_MAX_NS][256];
    const char   *ns_name_ptrs[CHANNEL_MAX_NS];
    size_t        num_ns;
    uint8_t       rdata_buf[CHANNEL_RDATA_CAP];  /* scratch space for rdata */
    size_t        rdata_off;
    dns_response_ext_t resp;  /* points into the arrays above */
    /* Internal state set by channel_buf_init */
    uint32_t      active_channels;
    char          domain[256];
} channel_buf_t;

/* Initialize cb and set up resp pointers.
 * active_channels is a bitmask of CHAN_* flags.
 * domain is the tunnel domain (e.g. "tunnel.example.com") */
void channel_buf_init(channel_buf_t *cb, uint32_t active_channels,
                      const char *domain);

/* Pack data[0..data_len-1] into cb->resp across all active channels.
 * Returns total bytes packed, or -1 on error. */
int channel_pack(channel_buf_t *cb, const uint8_t *data, size_t data_len);

/* Unpack data from a fully-parsed DNS response.
 * Extracts all channel fragments and reassembles into out[0..out_cap-1].
 * Returns total bytes unpacked, or -1 on error. */
int channel_unpack(const dns_parsed_response_t *parsed,
                   uint32_t active_channels,
                   uint8_t *out, size_t out_cap);
