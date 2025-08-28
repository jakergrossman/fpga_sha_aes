#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#define SHA256_MSGSCHED_U32S  (64)
#define SHA256_MSGSCHED_U8S   (SHA256_MSGSCHED_U32S*sizeof(uint32_t))

#define SHA256_BLOCK_BITS     (512U)
#define SHA256_BLOCK_U8S      (SHA256_BLOCK_BITS / 8)
#define SHA256_BLOCK_U32S     (SHA256_BLOCK_BITS / 32)
#define SHA256_BLOCK_U64S     (SHA256_BLOCK_BITS / 64)

#define SHA256_DIGEST_BITS    (256U)
#define SHA256_DIGEST_U8S     (SHA256_DIGEST_BITS / 8)
#define SHA224_DIGEST_BITS    (224U)
#define SHA224_DIGEST_U8S     (SHA224_DIGEST_BITS / 8)

int sha256(void *buf, size_t buflen, void *digest);
int sha224(void *buf, size_t buflen, void *digest);

#endif
