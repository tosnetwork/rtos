// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Test-only interposer. Only the selected fixture's Selection writes fail.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

ssize_t write(int fd, const void *buffer, size_t count) {
    const char *prefix = getenv("RTOS_TEST_SELECTION_PREFIX");
    const char *marker = getenv("RTOS_TEST_SELECTION_FAULT_MARKER");
    if (prefix && marker && count) {
        char link[64], path[PATH_MAX];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, path, sizeof(path) - 1);
        if (n > 0) {
            path[n] = 0;
            size_t length = strlen(prefix);
            if (!strncmp(path, prefix, length) && strlen(path + length) == 45
                && strspn(path + length, "0123456789abcdef") == 32
                && !strcmp(path + length + 32, "/selection.v1")) {
                struct stat info;
                if (!fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_size >= 28) {
                    int proof = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                    if (proof >= 0) {
                        const char message[] = "write selection.v1 after 28-byte header: ENOSPC\n";
                        ssize_t written = syscall(SYS_write, proof, message, sizeof(message) - 1);
                        if (written == (ssize_t)(sizeof(message) - 1)) fsync(proof);
                        close(proof);
                    }
                    errno = ENOSPC;
                    return -1;
                }
            }
        }
    }
    return syscall(SYS_write, fd, buffer, count);
}
