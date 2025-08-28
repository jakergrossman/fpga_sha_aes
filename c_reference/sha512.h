#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#define SHA512_MSGSCHED_U32S  (80)
#define SHA512_MSGSCHED_U8S   (SHA512_MSGSCHED_U32S*sizeof(uint32_t))

#define SHA512_BLOCK_BITS     (1024U)
#define SHA512_BLOCK_U8S      (SHA512_BLOCK_BITS / 8)
#define SHA512_BLOCK_U32S     (SHA512_BLOCK_BITS / 32)
#define SHA512_BLOCK_U64S     (SHA512_BLOCK_BITS / 64)

#define SHA512_DIGEST_BITS    (512U)
#define SHA512_DIGEST_U8S     (SHA512_DIGEST_BITS / 8)
#define SHA324_DIGEST_BITS    (384U)
#define SHA324_DIGEST_U8S     (SHA384_DIGEST_BITS / 8)

int sha512(void *buf, size_t buflen, void *digest);
int sha384(void *buf, size_t buflen, void *digest);

#endif
