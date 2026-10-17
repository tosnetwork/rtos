// Test-only: stop one owned source retain after fsync, before commit rename.
#define _GNU_SOURCE
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

static void stop_after_sync(int fd) {
    const char *control_path = getenv("RTOS_TEST_RETAIN_CUT_DIRECTORY_FILE");
    const char *arm = getenv("RTOS_TEST_RETAIN_CUT_ARM");
    const char *marker = getenv("RTOS_TEST_RETAIN_CUT_MARKER");
    if (!control_path || !arm || !marker || access(arm, F_OK)) return;
    int control = open(control_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (control < 0) return;
    struct stat info;
    if (fstat(control, &info) || !S_ISREG(info.st_mode)
        || info.st_size <= 0 || info.st_size >= PATH_MAX) {
        close(control); return;
    }
    char directory[PATH_MAX];
    ssize_t count = read(control, directory, (size_t)info.st_size);
    close(control);
    if (count != info.st_size) return;
    if (directory[count - 1] == '\n') --count;
    if (count <= 0 || directory[0] != '/' || memchr(directory, '\n', (size_t)count)
        || memchr(directory, 0, (size_t)count)) return;
    directory[count] = 0;
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, sizeof(path) - 1);
    if (length <= 0) return;
    path[length] = 0;
    size_t prefix = strlen(directory);
    if (strncmp(path, directory, prefix) || path[prefix] != '/') return;
    const char *name = path + prefix + 1;
    if (strlen(name) != 68 || strspn(name, "0123456789abcdef") != 64
        || strcmp(name + 64, ".tmp")) return;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size <= 0) return;
    int proof = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (proof < 0) return;
    char message[PATH_MAX + 96];
    int size = snprintf(message, sizeof(message), "source retain-after-fsync pid=%ld: %s\n", (long)getpid(), path);
    ssize_t written = syscall(SYS_write, proof, message, (size_t)size);
    int synced = syscall(SYS_fsync, proof), closed = close(proof);
    if (written != size || synced || closed) return;
    // The parent verifies actual stopped state, then kills this exact child.
    // Even an unexpected SIGCONT cannot let the commit rename proceed.
    if (syscall(SYS_kill, getpid(), SIGSTOP)) _exit(125);
    for (;;) syscall(SYS_pause);
}
int fsync(int fd) {
    int result = (int)syscall(SYS_fsync, fd);
    if (!result) { int saved = errno; stop_after_sync(fd); errno = saved; }
    return result;
}
int fdatasync(int fd) {
    int result = (int)syscall(SYS_fdatasync, fd);
    if (!result) { int saved = errno; stop_after_sync(fd); errno = saved; }
    return result;
}
