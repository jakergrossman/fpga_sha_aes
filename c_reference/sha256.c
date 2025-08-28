#include "sha256.h"

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include <arpa/inet.h>

struct sha256_hash
{
    uint32_t a, b, c, d, e, f, g, h;
};

static const uint32_t sha256_K[] = {
   0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static const struct sha256_hash sha256_fips180_hash =
{
    .a = 0x6A09E667,
    .b = 0xBB67AE85,
    .c = 0x3C6EF372,
    .d = 0xA54FF53A,
    .e = 0x510E527F,
    .f = 0x9B05688C,
    .g = 0x1F83D9AB,
    .h = 0x5BE0CD19,
};

static const struct sha256_hash sha224_fips180_hash =
{
    .a = 0xC1059ED8,
    .b = 0x367CD507,
    .c = 0x3070DD17,
    .d = 0xF70E5939,
    .e = 0xFFC00B31,
    .f = 0x68581511,
    .g = 0x64F98FA7,
    .h = 0xBEFA4FA4,
};


#define rotl(n,x) ((x) << (n) | ((x) >> (32 - (n))))
#define rotr(n,x) ((x) >> (n) | ((x) << (32 - (n))))
#define shr(n,x) ((x) >> (n))

static inline uint32_t sha256_S0(uint32_t x)
{
    return rotr(2,x) ^ rotr(13,x) ^ rotr(22,x);
}

static inline uint32_t sha256_S1(uint32_t x)
{
    return rotr(6,x) ^ rotr(11,x) ^ rotr(25,x);
}


static inline uint32_t sha256_s0(uint32_t x)
{
    return rotr(7,x) ^ rotr(18,x) ^ shr(3,x);
}

static inline uint32_t sha256_s1(uint32_t x)
{
    return rotr(17,x) ^ rotr(19,x) ^ shr(10,x);
}

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static int sha256update(struct sha256_hash *H, void *buf, size_t buflen, uint64_t *total)
{
    if (buflen < SHA256_BLOCK_U8S)
    {
        return -ERANGE;
    }

    uint32_t *M = buf;
    uint32_t W[16];
    struct sha256_hash work = *H;
    for (size_t t = 0; t < SHA256_MSGSCHED_U32S; t++)
    {
        uint32_t Wt = -1;
        if (t < 16)
        {
            Wt = W[t] = ntohl(M[t]);
        }
        else
        {
#define W_(t) W[(t) & 0xF]
            Wt = sha256_s1(W_(t-2)) + W_(t-7) + sha256_s0(W_(t-15)) + W_(t-16);
            W_(t)  = Wt;
#undef W_
        }

        uint32_t T1 = work.h + sha256_S1(work.e) + Ch(work.e,work.f,work.g) + sha256_K[t] + Wt;
        uint32_t T2 = sha256_S0(work.a) + Maj(work.a,work.b,work.c);
        work.h = work.g;
        work.g = work.f;
        work.f = work.e;
        work.e = work.d + T1;
        work.d = work.c;
        work.c = work.b;
        work.b = work.a;
        work.a = T1 + T2;
    }
    H->a += work.a;
    H->b += work.b;
    H->c += work.c;
    H->d += work.d;
    H->e += work.e;
    H->f += work.f;
    H->g += work.g;
    H->h += work.h;
    *total += SHA256_BLOCK_U8S;
    return 0;
}

static int sha256finish(struct sha256_hash *H, void *buf, size_t buflen, uint64_t total, void *digest, size_t diglen)
{
    size_t nblocks = buflen / SHA256_BLOCK_U8S;
    uint8_t *M = buf;
    for (size_t i = 0; i < nblocks; i++)
    {
        (void)sha256update(H, M, buflen, &total);
        M += SHA256_BLOCK_U8S;
        buflen -= SHA256_BLOCK_U8S;
    }

    uint64_t l = (total + buflen) * 8;
    uint8_t  msgbuf[SHA256_MSGSCHED_U8S] = { 0 };
    uint8_t  startpad = 0x80; /* use once */
    if (buflen >= (SHA256_BLOCK_U8S-sizeof(uint64_t)))
    {
        /* not enough space for 64-bit size, zero-fill this block */
        memcpy(msgbuf, M, buflen);
        msgbuf[buflen] = startpad;
        (void)sha256update(H, msgbuf, SHA256_BLOCK_U8S, &total);
        startpad = 0; /* we already placed 0x80, don't do it again */
        buflen = 0;   /* next block is all zeros */
    }

    size_t size_offset = SHA256_BLOCK_U8S - sizeof(uint64_t);
    memcpy(msgbuf, M, buflen); /* possibly nothing */
    msgbuf[buflen] = startpad;
    memset(msgbuf+buflen+1, 0,   size_offset - buflen - 1);

    /* put size as little endian */
    for (size_t i = 0; i < sizeof(l); i++)
    {
        msgbuf[size_offset + sizeof(l) - i - 1] = l & 0xFF;
        l >>= 8;
    }
    (void)sha256update(H, msgbuf, SHA256_BLOCK_U8S, &total);

    uint32_t *Hp = (uint32_t*)H;
    uint32_t *digestp = (uint32_t*)digest;
    for (size_t i = 0; i < diglen/sizeof(uint32_t); i++)
    {
        digestp[i] = htonl(Hp[i]);
    }

    return l;
}

int sha256(void *buf, size_t buflen, void *digest)
{
    struct sha256_hash H = sha256_fips180_hash;
    sha256finish(&H, buf, buflen, 0, digest, SHA256_DIGEST_U8S);
    return 0;
}

int sha224(void *buf, size_t buflen, void *digest)
{
    struct sha256_hash H = sha224_fips180_hash;
    sha256finish(&H, buf, buflen, 0, digest, SHA224_DIGEST_U8S);
    return 0;
}
