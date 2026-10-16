// Test-only: one exact source-ack file operation fails in the owned node.
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
static int fail_once(int fd, const char *operation, int error_number) {
    const char *target = getenv("RTOS_TEST_SOURCE_FAULT_FILE");
    const char *directory = getenv("RTOS_TEST_SOURCE_FAULT_DIRECTORY");
    const char *mode = getenv("RTOS_TEST_SOURCE_FAULT_MODE");
    const char *arm = getenv("RTOS_TEST_SOURCE_FAULT_ARM");
    const char *marker = getenv("RTOS_TEST_SOURCE_FAULT_MARKER");
    if ((!target && !directory) || !mode || strcmp(mode, operation) || !arm || !marker || access(arm, F_OK)) return 0;
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, sizeof(path) - 1);
    if (length <= 0) return 0;
    path[length] = 0;
    struct stat info;
    if (target) {
        if (strcmp(path, target)) return 0;
    } else {
        size_t prefix = strlen(directory);
        if (strncmp(path, directory, prefix) || path[prefix] != '/') return 0;
        const char *name = path + prefix + 1;
        if (strlen(name) != 72 || strspn(name, "0123456789abcdef") != 64 || strcmp(name + 64, ".ack.tmp")) return 0;
    }
    if (fstat(fd, &info) || !S_ISREG(info.st_mode)) return 0;
    if (!strcmp(operation, "sync-eio") && info.st_size <= 0) return 0;
    int proof = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (proof < 0) {
        if (errno == EEXIST) {
            if (!target && directory) { errno = error_number; return 1; }
            return 0;
        }
        return 1;
    }
    char message[PATH_MAX + 64];
    int size = snprintf(message, sizeof(message), "source %s: %s\n", operation, path);
    ssize_t written = syscall(SYS_write, proof, message, (size_t)size);
    int synced = syscall(SYS_fsync, proof), closed = close(proof);
    if (written != size || synced || closed) { errno = EIO; return 1; }
    errno = error_number;
    return 1;
}
ssize_t write(int fd, const void *bytes, size_t count) {
    if (count && fail_once(fd, "write-enospc", ENOSPC)) return -1;
    return syscall(SYS_write, fd, bytes, count);
}
int fsync(int fd) {
    if (fail_once(fd, "sync-eio", EIO)) return -1;
    return syscall(SYS_fsync, fd);
}
int fdatasync(int fd) {
    if (fail_once(fd, "sync-eio", EIO)) return -1;
    return syscall(SYS_fdatasync, fd);
}
