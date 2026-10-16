// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Test-only interposer, restricted to one fixture's Selection file.
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

static int selected(int fd, const char *mode) {
    const char *prefix = getenv("RTOS_TEST_SELECTION_PREFIX");
    const char *configured = getenv("RTOS_TEST_SELECTION_FAULT_MODE");
    if (!prefix || !configured || strcmp(mode, configured)
        || !getenv("RTOS_TEST_SELECTION_FAULT_MARKER")) return 0;
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n <= 0) return 0;
    path[n] = 0;
    size_t length = strlen(prefix);
    if (strncmp(path, prefix, length) || strlen(path + length) != 45
        || strspn(path + length, "0123456789abcdef") != 32
        || strcmp(path + length + 32, "/selection.v1")) return 0;
    struct stat info;
    return !fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_size >= 28;
}

static void record_fault(const char *message) {
    int proof = open(getenv("RTOS_TEST_SELECTION_FAULT_MARKER"),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (proof >= 0) {
        size_t length = strlen(message);
        ssize_t written = syscall(SYS_write, proof, message, length);
        if (written == (ssize_t)length) syscall(SYS_fsync, proof);
        close(proof);
    }
}

ssize_t write(int fd, const void *buffer, size_t count) {
    if (count && selected(fd, "selection-enospc")) {
        record_fault("write selection.v1 after 28-byte header: ENOSPC\n");
        errno = ENOSPC;
        return -1;
    }
    return syscall(SYS_write, fd, buffer, count);
}

int fsync(int fd) {
    if (selected(fd, "selection-sync-eio")) {
        record_fault("fsync selection.v1 after complete manifest: EIO\n");
        errno = EIO;
        return -1;
    }
    return syscall(SYS_fsync, fd);
}
