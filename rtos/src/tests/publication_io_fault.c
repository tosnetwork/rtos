// Isolated fixture: fail the next exact acceptance worker/body fd synchronization.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int selected(int fd, char path[PATH_MAX]) {
    const char *control = getenv("RTOS_TEST_PUBLICATION_IO_CONTROL");
    if (!control || control[0] != '/') return 0;
    char target[PATH_MAX];
    int length = snprintf(target, sizeof(target), "%s/target.native", control);
    if (length <= 0 || length >= (int)sizeof(target)) return 0;
    int input = open(target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) return 0;
    struct stat info;
    if (fstat(input, &info) || !S_ISREG(info.st_mode) || info.st_size <= 0
        || info.st_size >= PATH_MAX + 128) { close(input); return 0; }
    char bytes[PATH_MAX + 128];
    ssize_t count = read(input, bytes, sizeof(bytes) - 1);
    close(input);
    if (count != info.st_size || memchr(bytes, 0, (size_t)count)) return 0;
    bytes[count] = 0;
    unsigned long pid, tid;
    unsigned long long dev, ino;
    int consumed = 0;
    if (sscanf(bytes, "%lu %lu %llu %llu%n", &pid, &tid, &dev, &ino, &consumed) != 4
        || bytes[consumed] != '\n' || pid != (unsigned long)getpid()
        || tid != (unsigned long)syscall(SYS_gettid)) return 0;
    const char *expected = bytes + consumed + 1;
    size_t path_length = strlen(expected);
    if (path_length < 3 || expected[0] != '/' || expected[path_length - 1] != '\n'
        || memchr(expected, '\n', path_length - 1) || memchr(expected, '\r', path_length)) return 0;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t actual_length = readlink(link, path, PATH_MAX - 1);
    if (actual_length <= 0 || (size_t)actual_length != path_length - 1) return 0;
    path[actual_length] = 0;
    if (memcmp(path, expected, (size_t)actual_length)) return 0;
    return !fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_size > 0
        && dev == (unsigned long long)info.st_dev && ino == (unsigned long long)info.st_ino;
}
static int fail_sync(int fd, const char *operation) {
    char path[PATH_MAX];
    if (!selected(fd, path)) return 0;
    const char *control = getenv("RTOS_TEST_PUBLICATION_IO_CONTROL");
    char marker[PATH_MAX];
    int length = snprintf(marker, sizeof(marker), "%s/native-error.marker", control);
    if (length <= 0 || length >= (int)sizeof(marker)) return 0;
    int output = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output < 0) return 0;
    char message[PATH_MAX + 128];
    length = snprintf(message, sizeof(message), "publication sync-eio pid=%ld tid=%ld syscall=%s errno=%d: %s\n",
        (long)getpid(), syscall(SYS_gettid), operation, EIO, path);
    ssize_t written = syscall(SYS_write, output, message, (size_t)length);
    int synced = syscall(SYS_fsync, output), closed = close(output);
    if (written != length || synced || closed) _exit(125);
    const char *return_eio = getenv("RTOS_TEST_PUBLICATION_IO_RETURN_EIO");
    if (return_eio && !strcmp(return_eio, "1")) { errno = EIO; return 1; }
    // The owned parent verifies T state before SIGKILL. On SIGCONT the normal
    // caller receives EIO; no success callback is manufactured by this fixture.
    if (syscall(SYS_kill, getpid(), SIGSTOP)) _exit(125);
    errno = EIO;
    return 1;
}
int fsync(int fd) {
    if (fail_sync(fd, "fsync")) return -1;
    int (*next)(int) = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    return next ? next(fd) : (int)syscall(SYS_fsync, fd);
}
int fdatasync(int fd) {
    if (fail_sync(fd, "fdatasync")) return -1;
    int (*next)(int) = (int (*)(int))dlsym(RTLD_NEXT, "fdatasync");
    return next ? next(fd) : (int)syscall(SYS_fdatasync, fd);
}
