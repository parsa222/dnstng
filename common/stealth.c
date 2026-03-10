#include "stealth.h"
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <math.h>

/* ------------------------------------------------------------------ */
/* Random bytes: getrandom() syscall, fallback to /dev/urandom         */
/* ------------------------------------------------------------------ */

void stealth_random_bytes(uint8_t *buf, size_t len)
{
    ssize_t ret;

    if (!buf || len == 0) {
        return;
    }

    /* Try getrandom syscall */
    ret = syscall(SYS_getrandom, buf, len, 0);
    if (ret == (ssize_t)len) {
        return;
    }

    /* Fallback: /dev/urandom */
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, len);
            close(fd);
            if (n == (ssize_t)len) {
                return;
            }
        }
    }

    /* Last resort: zero-fill (should not happen in practice) */
    memset(buf, 0, len);
}

uint32_t stealth_rand32(void)
{
    uint32_t val;
    stealth_random_bytes((uint8_t *)&val, sizeof(val));
    return val;
}

/* Returns delay_ms * (0.8 + rand * 0.4) where rand is in [0,1) */
uint64_t stealth_jitter(uint64_t delay_ms)
{
    double   r;
    uint32_t rnd = stealth_rand32();

    r = (double)rnd / 4294967296.0; /* [0,1) */
    return (uint64_t)((double)delay_ms * (0.8 + r * 0.4));
}

/* Shannon entropy: H = -sum(p_i * log2(p_i)) */
double stealth_entropy(const uint8_t *data, size_t len)
{
    size_t   counts[256];
    size_t   i;
    double   entropy = 0.0;

    if (!data || len == 0) {
        return 0.0;
    }

    memset(counts, 0, sizeof(counts));
    for (i = 0; i < len; i++) {
        counts[data[i]]++;
    }

    for (i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

/* ------------------------------------------------------------------ */
/* Noise domains                                                        */
/* ------------------------------------------------------------------ */

const char *const NOISE_DOMAINS[NOISE_DOMAIN_COUNT] = {
    "google.com",        "youtube.com",       "facebook.com",
    "twitter.com",       "instagram.com",     "linkedin.com",
    "amazon.com",        "apple.com",         "microsoft.com",
    "github.com",        "stackoverflow.com", "reddit.com",
    "wikipedia.org",     "cloudflare.com",    "netflix.com",
    "twitch.tv",         "discord.com",       "slack.com",
    "zoom.us",           "dropbox.com",       "spotify.com",
    "paypal.com",        "ebay.com",          "yahoo.com",
    "bing.com",          "duckduckgo.com",    "archive.org",
    "mozilla.org",       "wordpress.com",     "blogger.com",
    "tumblr.com",        "medium.com",        "quora.com",
    "pinterest.com",     "snapchat.com",      "tiktok.com",
    "whatsapp.com",      "telegram.org",      "signal.org",
    "protonmail.com",    "gmail.com",         "outlook.com",
    "icloud.com",        "office.com",        "drive.google.com",
    "docs.google.com",   "maps.google.com",   "play.google.com",
    "store.steampowered.com", "epicgames.com","roblox.com",
    "twitch.tv",         "youtube.com",       "vimeo.com",
    "dailymotion.com",   "soundcloud.com",    "bandcamp.com",
    "flickr.com",        "imgur.com",         "giphy.com",
    "cdn.cloudflare.com","fastly.net",        "akamai.net",
    "aws.amazon.com",    "azure.microsoft.com","gcp.google.com",
    "heroku.com",        "digitalocean.com",  "linode.com",
    "vultr.com",         "hetzner.com",       "ovh.net",
    "godaddy.com",       "namecheap.com",     "cloudns.net",
    "nist.gov",          "iana.org",          "icann.org",
    "verisign.com",      "symantec.com",      "digicert.com",
    "letsencrypt.org",   "certbot.eff.org",   "eff.org",
    "aclu.org",          "amnesty.org",       "greenpeace.org",
    "who.int",           "un.org",            "nato.int",
    "bbc.com",           "cnn.com",           "reuters.com",
    "apnews.com",        "theguardian.com",   "nytimes.com",
    "washingtonpost.com","wsj.com",           "bloomberg.com",
    "forbes.com",
};
