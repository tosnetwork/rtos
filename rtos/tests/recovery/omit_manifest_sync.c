// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Test-only causal control: omit sync only for one isolated fixture's selected recovery file.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int selected(int fd, char path[PATH_MAX]) {
    const char *root = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_ROOT");
    const char *marker = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER");
    const char *file = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE");
    if (file && (!strcmp(file, "ready-wal") || !strcmp(file, "committed-wal") || !strcmp(file, "cleaned-wal") || !strcmp(file, "root-wal"))) file = "ready.v1";
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

static atomic_int wal_armed = 0;
static char wal_prefix[PATH_MAX];

static int selected_wal(int fd, char path[PATH_MAX]) {
    if (atomic_load_explicit(&wal_armed, memory_order_acquire) != 1) return 0;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, PATH_MAX - 1);
    if (length <= 0) return 0;
    path[length] = 0;
    size_t prefix = strlen(wal_prefix);
    if (strncmp(path, wal_prefix, prefix)) return 0;
    const char *leaf = path + prefix;
    size_t digits = strspn(leaf, "0123456789");
    struct stat info;
    return digits && !strcmp(leaf + digits, ".log") && !fstat(fd, &info)
        && S_ISREG(info.st_mode) && info.st_size > 0;
}

static int selected_lease_wal(int fd, char path[PATH_MAX]) {
    const char *root = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_ROOT");
    const char *arm = getenv("RTOS_TEST_ROOT_WAL_ARM");
    if (!root || !*root || !arm || access(arm, F_OK)
        || !getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER")) return 0;
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
    const char *mode = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE");
    const char *parent = mode && !strcmp(mode, "validator-wal") ? "/node_db/catchains/" : "/node_db/db/";
    size_t parent_length = strlen(parent);
    if (!end || strncmp(fixture, ".tmp", 4) || strncmp(end, parent, parent_length)) return 0;
    const char *leaf = end + parent_length;
    size_t digits = strspn(leaf, "0123456789");
    struct stat info;
    return digits && !strcmp(leaf + digits, ".log") && !fstat(fd, &info)
        && S_ISREG(info.st_mode) && info.st_size > 0;
}

static int sync_or_omit(int fd, long operation, const char *name) {
    char path[PATH_MAX];
    const char *mode = getenv("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE");
    if (mode && (!strcmp(mode, "lease-wal") || !strcmp(mode, "validator-wal"))) {
        if (!selected_lease_wal(fd, path)) return syscall(operation, fd);
    } else if (mode && (!strcmp(mode, "ready-wal") || !strcmp(mode, "committed-wal") || !strcmp(mode, "cleaned-wal") || !strcmp(mode, "root-wal"))) {
        if (!atomic_load_explicit(&wal_armed, memory_order_acquire) && selected(fd, path)) {
            int result = syscall(operation, fd);
            if (result) return result;
            int idle = 0;
            if (!atomic_compare_exchange_strong_explicit(&wal_armed, &idle, -1,
                    memory_order_acq_rel, memory_order_acquire)) return 0;
            char *parent = strstr(path, "/node_db/archive/recovery/");
            if (!parent) { errno = EINVAL; return -1; }
            *parent = 0;
            int length = snprintf(wal_prefix, sizeof(wal_prefix), "%s/node_db/db/", path);
            if (length <= 0 || (size_t)length >= sizeof(wal_prefix)) { errno = ENAMETOOLONG; return -1; }
            atomic_store_explicit(&wal_armed, 1, memory_order_release);
            return 0;
        }
        if (!selected_wal(fd, path)) return syscall(operation, fd);
        if (!strcmp(mode, "committed-wal") || !strcmp(mode, "cleaned-wal") || !strcmp(mode, "root-wal")) {
            const char *armed = getenv("RTOS_TEST_ROOT_WAL_ARM");
            if (!armed || access(armed, F_OK)) return syscall(operation, fd);
        }
    } else if (!selected(fd, path)) return syscall(operation, fd);
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
