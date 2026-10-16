// Test-only: fail exactly one owned dynamic-state WAL durability barrier.
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
static int sync_or_fail(int fd, long operation) {
    const char *prefix = getenv("RTOS_TEST_STATE_FAULT_PREFIX");
    const char *arm = getenv("RTOS_TEST_ROOT_WAL_ARM");
    const char *marker = getenv("RTOS_TEST_STATE_FAULT_MARKER");
    if (!prefix || !arm || !marker || access(arm, F_OK)) return syscall(operation, fd);
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, sizeof(path) - 1);
    if (length <= 0) return syscall(operation, fd);
    path[length] = 0;
    size_t n = strlen(prefix);
    if (!n || prefix[n-1] != '/' || strncmp(path, prefix, n)) return syscall(operation, fd);
    const char *leaf = path + n;
    size_t digits = strspn(leaf, "0123456789");
    struct stat info;
    if (!digits || strcmp(leaf + digits, ".log") || fstat(fd, &info)
        || !S_ISREG(info.st_mode) || info.st_size <= 0) return syscall(operation, fd);
    int proof = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (proof < 0) { if (errno == EEXIST) return syscall(operation, fd); return -1; }
    char message[PATH_MAX + 32];
    int size = snprintf(message, sizeof(message), "state WAL sync EIO: %s\n", path);
    ssize_t written = syscall(SYS_write, proof, message, (size_t)size);
    int synced = syscall(SYS_fsync, proof), closed = close(proof);
    if (written != size || synced || closed) { errno = EIO; return -1; }
    errno = EIO;
    return -1;
}
int fsync(int fd) { return sync_or_fail(fd, SYS_fsync); }
int fdatasync(int fd) { return sync_or_fail(fd, SYS_fdatasync); }
