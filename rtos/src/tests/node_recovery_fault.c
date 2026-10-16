// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Test-only interposer, restricted to one fixture's recovery operation.
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

static int selected(int fd, const char *mode, const char *suffix) {
    const char *prefix = getenv("RTOS_TEST_RECOVERY_PREFIX");
    const char *configured = getenv("RTOS_TEST_RECOVERY_FAULT_MODE");
    if (!prefix || !configured || strcmp(mode, configured)
        || !getenv("RTOS_TEST_RECOVERY_FAULT_MARKER")) return 0;
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n <= 0) return 0;
    path[n] = 0;
    size_t length = strlen(prefix);
    if (strncmp(path, prefix, length) || strlen(path + length) != 32 + strlen(suffix)
        || strspn(path + length, "0123456789abcdef") != 32
        || strcmp(path + length + 32, suffix)) return 0;
    struct stat info;
    if (fstat(fd, &info)) return 0;
    if (*suffix) return S_ISREG(info.st_mode) && info.st_size >= 28;
    // Directory failure is armed only once the complete Selection is present.
    if (!S_ISDIR(info.st_mode)) return 0;
    return !fstatat(fd, "selection.v1", &info, AT_SYMLINK_NOFOLLOW)
        && S_ISREG(info.st_mode) && info.st_size > 28;
}

static void record_fault(const char *message) {
    int proof = open(getenv("RTOS_TEST_RECOVERY_FAULT_MARKER"),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (proof >= 0) {
        size_t length = strlen(message);
        ssize_t written = syscall(SYS_write, proof, message, length);
        if (written == (ssize_t)length) syscall(SYS_fsync, proof);
        close(proof);
    }
}

ssize_t write(int fd, const void *buffer, size_t count) {
    if (count && selected(fd, "selection-enospc", "/selection.v1")) {
        record_fault("write selection.v1 after 28-byte header: ENOSPC\n");
        errno = ENOSPC;
        return -1;
    }
    if (count && selected(fd, "ready-enospc", "/ready.v1")) {
        record_fault("write ready.v1 after 28-byte header: ENOSPC\n");
        errno = ENOSPC;
        return -1;
    }
    return syscall(SYS_write, fd, buffer, count);
}

int fsync(int fd) {
    if (selected(fd, "selection-sync-eio", "/selection.v1")) {
        record_fault("fsync selection.v1 after complete manifest: EIO\n");
        errno = EIO;
        return -1;
    }
    if (selected(fd, "ready-sync-eio", "/ready.v1")) {
        record_fault("fsync ready.v1 after complete manifest: EIO\n");
        errno = EIO;
        return -1;
    }
    if (selected(fd, "operation-sync-eio", "")) {
        record_fault("fsync operation directory after Selection: EIO\n");
        errno = EIO;
        return -1;
    }
    return syscall(SYS_fsync, fd);
}
