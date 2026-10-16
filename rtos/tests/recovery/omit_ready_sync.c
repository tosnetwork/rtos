// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Test-only causal control: omit sync only for one isolated fixture's Ready.
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

static int selected(int fd, char path[PATH_MAX]) {
    const char *root = getenv("RTOS_TEST_OMIT_READY_SYNC_ROOT");
    const char *marker = getenv("RTOS_TEST_OMIT_READY_SYNC_MARKER");
    if (!root || !marker || !*root) return 0;
    size_t prefix = strlen(root);
    if (root[prefix - 1] != '/') return 0;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, PATH_MAX - 1);
    if (length <= 0) return 0;
    path[length] = 0;
    if (strncmp(path, root, prefix)) return 0;
    const char *fixture = path + prefix;
    const char *end = strchr(fixture, '/');
    if (!end || end == fixture || strncmp(fixture, ".tmp", 4)) return 0;
    const char parent[] = "/node_db/archive/recovery/";
    if (strncmp(end, parent, sizeof(parent) - 1)) return 0;
    const char *operation = end + sizeof(parent) - 1;
    if (strlen(operation) != 32 + strlen("/ready.v1")
        || strspn(operation, "0123456789abcdef") != 32
        || strcmp(operation + 32, "/ready.v1")) return 0;
    struct stat info;
    return !fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_size > 28;
}

static int sync_or_omit(int fd, long operation, const char *name) {
    char path[PATH_MAX];
    if (!selected(fd, path)) return syscall(operation, fd);
    int proof = open(getenv("RTOS_TEST_OMIT_READY_SYNC_MARKER"),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (proof < 0) {
        // Atomic, cross-process one-shot claim; subsequent recovery attempts
        // retain their normal sync behavior.
        if (errno == EEXIST) return syscall(operation, fd);
        return -1;
    }
    char message[PATH_MAX + 64];
    int length = snprintf(message, sizeof(message), "%s omitted: %s\n", name, path);
    ssize_t written = syscall(SYS_write, proof, message, (size_t)length);
    int synced = syscall(SYS_fsync, proof);
    int closed = close(proof);
    if (written != length || synced || closed) { errno = EIO; return -1; }
    return 0;
}

int fsync(int fd) { return sync_or_omit(fd, SYS_fsync, "fsync"); }
int fdatasync(int fd) { return sync_or_omit(fd, SYS_fdatasync, "fdatasync"); }
