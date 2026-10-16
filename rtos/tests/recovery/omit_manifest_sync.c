// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Test-only causal control: omit sync only for one isolated fixture's selected recovery file.
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
    const char *root = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_ROOT");
    const char *marker = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER");
    const char *file = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE");
    if (!root || !marker || !*root || !file
        || (strcmp(file, "ready.v1") && strcmp(file, "selection.v1") && strcmp(file, "stage"))) return 0;
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
    const char *operation;
    const char parent[] = "/node_db/archive/recovery/";
    if (!strncmp(end, parent, sizeof(parent) - 1)) {
        operation = end + sizeof(parent) - 1;
    } else if (!strcmp(file, "stage") && !strncmp(end, "/epochs/epoch_", 14)) {
        const char *number = end + 14;
        size_t digits = strspn(number, "0123456789");
        const char suffix[] = "/archive/recovery/";
        if (!digits || strncmp(number + digits, suffix, sizeof(suffix) - 1)) return 0;
        operation = number + digits + sizeof(suffix) - 1;
    } else return 0;
    if (strlen(operation) < 34 || strspn(operation, "0123456789abcdef") != 32
        || operation[32] != '/') return 0;
    const char *leaf = operation + 33;
    if (!strcmp(file, "stage")) {
        if (strlen(leaf) != 75 || strncmp(leaf, "stage-", 6)
            || strspn(leaf + 6, "0123456789abcdef") != 64
            || strcmp(leaf + 70, ".pack")) return 0;
    } else if (strcmp(leaf, file)) return 0;
    struct stat info;
    return !fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_size > 28;
}

static int sync_or_omit(int fd, long operation, const char *name) {
    char path[PATH_MAX];
    if (!selected(fd, path)) return syscall(operation, fd);
    int proof = open(getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER"),
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
