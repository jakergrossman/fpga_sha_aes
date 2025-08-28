// SPDX-License-Identifier: CC0-1.0
/* shaXsum.c - multi-binary reference executable for SHA-2 hash functions (sha224, sha256, sha384, sha512) */

#include "sha256.h"
#include "sha512.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <getopt.h>

static const struct proginfo {
    const char *progname;
    size_t digest_size;
    int (*shafn)(void *buf, size_t len, void *digest);
} progs[] = {
    { "sha256", SHA256_DIGEST_U8S, sha256, },
    { "sha224", SHA224_DIGEST_U8S, sha224, },
    { 0 },
};

int main(int argc, char *argv[])
{
    const struct proginfo *chosen_program = &progs[0];

    const char *progname = basename(argv[0]);
    for (const struct proginfo *info = progs; info->progname; info++)
    {
        if (!strcmp(info->progname, progname))
        {
            chosen_program = info;
            break;
        }
    }
    progname = chosen_program->progname;

    bool digest_only = false;

    char ch;
    while (-1 != (ch = getopt(argc, argv, ":dh")))
    {
        switch (ch)
        {
        case 'd':
            digest_only = true;
            break;
        default:
            break;
        }
    }


    for (int i = optind; i < argc; i++)
    {
        int fd = open(argv[i], O_RDONLY);
        if (fd == -1)
        {
            fprintf(stderr, "%s: %s: %s: %s\n", progname, "open", argv[i], strerror(errno));
            continue;
        }

        struct stat statbuf;
        if (fstat(fd, &statbuf) == -1)
        {
            fprintf(stderr, "%s: %s: %s: %s\n", progname, "fstat", argv[i], strerror(errno));
            continue;
        }

        void *data = NULL;
        size_t buflen = statbuf.st_size;
        if (buflen)
        {
            data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (data == MAP_FAILED)
            {
                fprintf(stderr, "%s: %s: %s\n", progname, "mmap", strerror(errno));
                continue;
            }
        }

        uint8_t digest[512];
        chosen_program->shafn(data, statbuf.st_size, &digest);
        for (size_t i = 0; i < chosen_program->digest_size; i++)
        {
            char map[] = "0123456789abcdef";
            putc(map[(digest[i] >> 4) & 0xF], stdout);
            putc(map[(digest[i] & 0xF)], stdout);
        }
        if (!digest_only)
        {
            putc(' ', stdout);
            putc(' ', stdout);
            puts(argv[i]);
        }
        else
        {
            putc('\n', stdout);
        }
    }
}
