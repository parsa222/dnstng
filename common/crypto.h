/*
 * crypto.h — Lightweight payload encryption for DNS tunnel.
 *
 * Inspired by dnscat2's encryption layer. Uses a pre-shared key (PSK)
 * to derive a per-packet keystream via CRC-based PRNG, then XORs the
 * payload. This is NOT a cryptographically strong cipher — it's designed
 * to defeat passive DPI inspection of DNS tunnel payloads while adding
 * minimal overhead (2-byte nonce prepended to each encrypted payload).
 *
 * Wire format of encrypted payload:
 *   [nonce_hi][nonce_lo][encrypted_data...]
 *
 * The nonce is incremented for each packet and combined with the PSK
 * hash to seed the keystream.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include "util.h"
#include <stdint.h>
#include <stddef.h>

/* Maximum PSK length in bytes */
#define CRYPTO_PSK_MAX  64

/* Nonce size prepended to encrypted payloads */
#define CRYPTO_NONCE_SIZE  2

typedef struct {
    uint8_t  key_hash[32];   /* SHA-256-like hash of the PSK */
    uint16_t tx_nonce;       /* Outgoing nonce (incremented per packet) */
    uint16_t rx_nonce;       /* Last received nonce (anti-replay) */
    int      enabled;        /* 0 = no encryption, 1 = active */
} crypto_ctx_t;

/* Initialize crypto context. If psk is NULL or psk_len is 0, encryption
 * is disabled. Returns ERR_OK on success. */
void crypto_init(crypto_ctx_t *ctx, const uint8_t *psk, size_t psk_len);

/* Encrypt data in-place. Prepends 2-byte nonce.
 * Input:  plaintext in buf[0..data_len-1]
 * Output: [nonce_hi][nonce_lo][ciphertext...] in out[0..data_len+1]
 * out_cap must be >= data_len + CRYPTO_NONCE_SIZE.
 * Returns total output length (data_len + 2), or -1 on error. */
int crypto_encrypt(crypto_ctx_t *ctx,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_cap);

/* Decrypt data in-place. Reads 2-byte nonce, then decrypts.
 * Input:  [nonce_hi][nonce_lo][ciphertext...] in buf[0..buf_len-1]
 * Output: plaintext in out[0..buf_len-3]
 * out_cap must be >= buf_len - CRYPTO_NONCE_SIZE.
 * Returns plaintext length, or -1 on error. */
int crypto_decrypt(crypto_ctx_t *ctx,
                   const uint8_t *buf, size_t buf_len,
                   uint8_t *out, size_t out_cap);

/* Derive a 32-byte key hash from a PSK. Used internally. */
void crypto_derive_key(const uint8_t *psk, size_t psk_len,
                       uint8_t out[32]);

#endif /* CRYPTO_H */
