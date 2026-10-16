// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Test-only interposer, restricted to one fixture's recovery operation.
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

static atomic_int wal_armed = 0;

static int fail_wal_sync(int fd) {
    if (!atomic_load_explicit(&wal_armed, memory_order_acquire)) return 0;
    const char *root = getenv("RTOS_TEST_FIXTURE_ROOT");
    const char *mode = getenv("RTOS_TEST_RECOVERY_FAULT_MODE");
    if (!root || !mode) return 0;
    char link[64], path[PATH_MAX], prefix[PATH_MAX];
    int epoch = !strcmp(mode, "wal-epoch-enrollment-eio");
    int size = snprintf(prefix, sizeof(prefix), epoch ? "%s/epochs/epoch_" : "%s/node_db/db/", root);
    if (size <= 0 || (size_t)size >= sizeof(prefix)) return 0;
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n <= 0) return 0;
    path[n] = 0;
    if (strncmp(path, prefix, size)) return 0;
    const char *name = path + size;
    if (epoch) {
        size_t number = strspn(name, "0123456789");
        const char database[] = "/archive_db/";
        if (!number || strncmp(name + number, database, sizeof(database) - 1)) return 0;
        name += number + sizeof(database) - 1;
    }
    size_t digits = strspn(name, "0123456789");
    if (!digits || strcmp(name + digits, ".log")) return 0;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode)) return 0;
    if (!strcmp(mode, "wal-ready-sync-eio"))
        record_fault("main WAL sync after Ready fsync: EIO\n");
    else if (!strcmp(mode, "wal-publish-sync-eio"))
        record_fault("main WAL sync after canonical replacement: EIO\n");
    else if (epoch)
        record_fault("epoch WAL sync after Selection fsync: EIO\n");
    else return 0;
    errno = EIO;
    return 1;
}

int fdatasync(int fd) {
    if (fail_wal_sync(fd)) return -1;
    return syscall(SYS_fdatasync, fd);
}

// Publish the exact renamed pathname once; readers never observe a partial path.
static atomic_int renamed_state = 0;
static char renamed_path[PATH_MAX];

static int stage_directory(int fd, const char *mode) {
    const char *root = getenv("RTOS_TEST_FIXTURE_ROOT");
    const char *configured = getenv("RTOS_TEST_RECOVERY_FAULT_MODE");
    if (!root || !configured || strcmp(mode, configured)
        || !getenv("RTOS_TEST_RECOVERY_FAULT_MARKER")) return 0;
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n <= 0) return 0;
    path[n] = 0;
    size_t length = strlen(root);
    if (strncmp(path, root, length) || path[length] != '/') return 0;
    const char *operation = strrchr(path, '/');
    const char parent[] = "/archive/recovery/";
    if (!operation || strlen(operation + 1) != 32
        || strspn(operation + 1, "0123456789abcdef") != 32
        || (size_t)(operation + 1 - path) < sizeof(parent) - 1
        || strncmp(operation + 1 - (sizeof(parent) - 1), parent, sizeof(parent) - 1)) return 0;
    struct stat info;
    return !fstat(fd, &info) && S_ISDIR(info.st_mode);
}

int renameat(int olddir, const char *old, int newdir, const char *new) {
    int stage = strlen(old) == 75 && !strncmp(old, "stage-", 6)
        && strspn(old + 6, "0123456789abcdef") == 64 && !strcmp(old + 70, ".pack");
    if (stage && stage_directory(olddir, "publish-rename-eio")) {
        record_fault("renameat staged package before replacement: EIO\n");
        errno = EIO;
        return -1;
    }
    int arm_directory = stage && stage_directory(olddir, "publish-directory-sync-eio");
    int arm = arm_directory || (stage && stage_directory(olddir, "publish-sync-eio"));
    int arm_wal = stage && stage_directory(olddir, "wal-publish-sync-eio");
    char target[PATH_MAX];
    if (arm) {
        char link[64];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", newdir);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n <= 0 || strchr(new, '/') || (size_t)n + 1 + strlen(new) >= sizeof(target)) arm = 0;
        else if (arm_directory) target[n] = 0;
        else { target[n] = '/'; strcpy(target + n + 1, new); }
    }
    int result = syscall(SYS_renameat, olddir, old, newdir, new);
    if (!result && arm_wal) atomic_store_explicit(&wal_armed, 1, memory_order_release);
    int expected = 0;
    if (!result && arm && atomic_compare_exchange_strong(&renamed_state, &expected, 1)) {
        strcpy(renamed_path, target);
        atomic_store_explicit(&renamed_state, 2, memory_order_release);
    }
    return result;
}

int fsync(int fd) {
    if (fail_wal_sync(fd)) return -1;
    if (selected(fd, "wal-ready-sync-eio", "/ready.v1")
        || selected(fd, "wal-epoch-enrollment-eio", "/selection.v1")) {
        int result = syscall(SYS_fsync, fd);
        if (!result) atomic_store_explicit(&wal_armed, 1, memory_order_release);
        return result;
    }
    if (atomic_load_explicit(&renamed_state, memory_order_acquire) == 2) {
        char link[64], path[PATH_MAX];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, path, sizeof(path) - 1);
        if (n > 0) {
            path[n] = 0;
            if (!strcmp(path, renamed_path)) {
                const char *mode = getenv("RTOS_TEST_RECOVERY_FAULT_MODE");
                if (mode && !strcmp(mode, "publish-directory-sync-eio"))
                    record_fault("fsync canonical directory after replacement: EIO\n");
                else record_fault("fsync replaced canonical package: EIO\n");
                errno = EIO;
                return -1;
            }
        }
    }

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
