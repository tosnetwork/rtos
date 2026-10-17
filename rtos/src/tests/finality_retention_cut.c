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

static int selected_path(int fd, char path[PATH_MAX], int allow_empty) {
    const char *control_path = getenv("RTOS_TEST_RETAIN_CUT_DIRECTORY_FILE");
    const char *arm = getenv("RTOS_TEST_RETAIN_CUT_ARM");
    if (!control_path || !arm || access(arm, F_OK)) return 0;
    int control = open(control_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (control < 0) return 0;
    struct stat info;
    if (fstat(control, &info) || !S_ISREG(info.st_mode)
        || info.st_size <= 0 || info.st_size >= PATH_MAX) {
        close(control); return 0;
    }
    char directory[PATH_MAX];
    ssize_t count = read(control, directory, (size_t)info.st_size);
    close(control);
    if (count != info.st_size) return 0;
    if (directory[count - 1] == '\n') --count;
    if (count <= 0 || directory[0] != '/' || memchr(directory, '\n', (size_t)count)
        || memchr(directory, 0, (size_t)count)) return 0;
    directory[count] = 0;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, PATH_MAX - 1);
    if (length <= 0) return 0;
    path[length] = 0;
    size_t prefix = strlen(directory);
    if (strncmp(path, directory, prefix) || path[prefix] != '/') return 0;
    const char *name = path + prefix + 1;
    if (strlen(name) != 68 || strspn(name, "0123456789abcdef") != 64
        || strcmp(name + 64, ".tmp")) return 0;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || (!allow_empty && info.st_size <= 0)) return 0;
    return 1;
}
static int save_intended(const void *bytes, size_t count) {
    const char *target = getenv("RTOS_TEST_RETAIN_CUT_INTENDED");
    if (!target || !count || count > ((size_t)64 << 20)) return 0;
    int fd = open(target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return 0;
    size_t offset = 0;
    while (offset < count) {
        ssize_t written = syscall(SYS_write, fd, (const char *)bytes + offset, count - offset);
        if (written <= 0) { close(fd); return 0; }
        offset += (size_t)written;
    }
    int synced = syscall(SYS_fsync, fd), closed = close(fd);
    return !synced && !closed;
}
static void publish_stop(const char *path, const char *point) {
    const char *marker = getenv("RTOS_TEST_RETAIN_CUT_MARKER");
    if (!marker) return;
    int proof = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (proof < 0) return;
    char message[PATH_MAX + 96];
    int size = snprintf(message, sizeof(message), "source retain-%s pid=%ld: %s\n", point, (long)getpid(), path);
    ssize_t written = syscall(SYS_write, proof, message, (size_t)size);
    int synced = syscall(SYS_fsync, proof), closed = close(proof);
    if (written != size || synced || closed) return;
    // The parent verifies actual stopped state, then kills this exact child.
    // Even an unexpected SIGCONT cannot let the commit rename proceed.
    if (syscall(SYS_kill, getpid(), SIGSTOP)) _exit(125);
    for (;;) syscall(SYS_pause);
}
static void stop_after_sync(int fd) {
    const char *point = getenv("RTOS_TEST_RETAIN_CUT_POINT");
    if (point && strcmp(point, "after-fsync")) return;
    char path[PATH_MAX];
    if (selected_path(fd, path, 0)) publish_stop(path, "after-fsync");
}
ssize_t write(int fd, const void *bytes, size_t count) {
    const char *point = getenv("RTOS_TEST_RETAIN_CUT_POINT");
    char path[PATH_MAX];
    if (point && count && (!strcmp(point, "before-write") || !strcmp(point, "after-partial-write"))
        && selected_path(fd, path, 1) && save_intended(bytes, count)) {
        if (!strcmp(point, "before-write")) publish_stop(path, point);
        if (count > 1) {
            ssize_t written = syscall(SYS_write, fd, bytes, count / 2);
            if (written > 0 && (size_t)written < count && !syscall(SYS_fsync, fd)) publish_stop(path, point);
            return written;
        }
    }
    return syscall(SYS_write, fd, bytes, count);
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
