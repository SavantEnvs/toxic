/* Shared helpers for toxic harnesses: write the fuzz input to a private temp file. */
#ifndef TOXIC_FUZZ_COMMON_H
#define TOXIC_FUZZ_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* Writes data to a new temp file under $TMPDIR (or /tmp); returns its path in buf, or -1. */
static int fuzz_write_tmp(char *buf, size_t buf_size, const char *suffix_tag, const uint8_t *data, size_t size)
{
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(buf, buf_size, "%s/toxic-fuzz-%s-XXXXXX", dir, suffix_tag);
    int fd = mkstemp(buf);
    if (fd < 0) {
        return -1;
    }
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, data + off, size - off);
        if (n <= 0) {
            close(fd);
            unlink(buf);
            return -1;
        }
        off += (size_t) n;
    }
    close(fd);
    return 0;
}
#endif
