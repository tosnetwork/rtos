// Test-only: one exact source-ack file operation fails in the owned node.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
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
    const char *directory_file = getenv("RTOS_TEST_SOURCE_FAULT_DIRECTORY_FILE");
    const char *mode = getenv("RTOS_TEST_SOURCE_FAULT_MODE");
    const char *arm = getenv("RTOS_TEST_SOURCE_FAULT_ARM");
    const char *marker = getenv("RTOS_TEST_SOURCE_FAULT_MARKER");
    if ((!target && !directory && !directory_file) || !mode || strcmp(mode, operation) || !arm || !marker || access(arm, F_OK)) return 0;
    // The owned interop fixture chooses one authenticated session only after
    // rotation. Read its exact directory, never a recursive or wildcard scope.
    char selected_directory[PATH_MAX];
    if (!target && directory_file) {
        int control = open(directory_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat control_info;
        if (control < 0) return 0;
        if (fstat(control, &control_info) || !S_ISREG(control_info.st_mode)
            || control_info.st_size <= 0 || control_info.st_size >= PATH_MAX) {
            close(control); return 0;
        }
        ssize_t count = read(control, selected_directory, (size_t)control_info.st_size);
        close(control);
        if (count != control_info.st_size) return 0;
        if (selected_directory[count - 1] == '\n') --count;
        if (count <= 0 || selected_directory[0] != '/'
            || memchr(selected_directory, '\n', (size_t)count)
            || memchr(selected_directory, 0, (size_t)count)) return 0;
        selected_directory[count] = 0;
        directory = selected_directory;
    }
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
// An independently armed intent cut is used only after the ACK failure was
// observed. It never changes the intent bytes or the successful sync result.
static int selected_intent(int fd, char path[PATH_MAX], struct stat *selected_info) {
    const char *arm = getenv("RTOS_TEST_SOURCE_INTENT_ARM");
    const char *marker = getenv("RTOS_TEST_SOURCE_INTENT_MARKER");
    const char *selector = getenv("RTOS_TEST_SOURCE_FAULT_DIRECTORY_FILE");
    struct stat info;
    if (!arm || !marker || !selector || lstat(arm, &info) || !S_ISREG(info.st_mode)) return 0;
    int control = open(selector, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (control < 0) return 0;
    char directory[PATH_MAX];
    if (fstat(control, &info) || !S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size >= PATH_MAX) {
        close(control); return 0;
    }
    ssize_t count = read(control, directory, (size_t)info.st_size);
    close(control);
    if (count != info.st_size) return 0;
    if (directory[count - 1] == '\n') --count;
    if (count <= 0 || directory[0] != '/' || memchr(directory, 0, (size_t)count)
        || memchr(directory, '\n', (size_t)count)) return 0;
    directory[count] = 0;
    char *base = strrchr(directory, '/');
    if (!base || strcmp(base, "/finality-pending")) return 0;
    *base = 0;
    char expected[PATH_MAX];
    int prefix = snprintf(expected, sizeof(expected), "%s/finality-intents/", directory);
    if (prefix <= 0 || prefix >= (int)sizeof(expected)) return 0;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, PATH_MAX - 1);
    if (length <= 0) return 0;
    path[length] = 0;
    if (strncmp(path, expected, (size_t)prefix)) return 0;
    const char *name = path + prefix;
    size_t digits = strspn(name, "0123456789");
    if (!digits || digits > 10 || name[digits] != '-' || (digits > 1 && name[0] == '0')) return 0;
    char *end;
    unsigned long slot = strtoul(name, &end, 10);
    if (slot > UINT32_MAX || end != name + digits) return 0;
    const char *hash = name + digits + 1;
    if (strlen(hash) != 68 || strspn(hash, "0123456789abcdef") != 64 || strcmp(hash + 64, ".tmp")) return 0;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 0 || info.st_size > (16 << 20)) return 0;
    *selected_info = info;
    return 1;
}
static void stop_intent_at(const char *path, const char *point) {
    const char *marker = getenv("RTOS_TEST_SOURCE_INTENT_MARKER");
    int proof = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (proof < 0) return;
    char message[PATH_MAX + 80];
    int size = snprintf(message, sizeof(message), "intent %s pid=%ld: %s\n", point, (long)getpid(), path);
    ssize_t written = syscall(SYS_write, proof, message, (size_t)size);
    int synced = syscall(SYS_fsync, proof), closed = close(proof);
    if (written != size || synced || closed) return;
    raise(SIGSTOP);
}
static void stop_synced_intent(int fd) {
    const char *point = getenv("RTOS_TEST_SOURCE_INTENT_POINT");
    if (point && strcmp(point, "after-fsync")) return;
    char path[PATH_MAX]; struct stat info;
    if (!selected_intent(fd, path, &info) || info.st_size <= 0) return;
    stop_intent_at(path, "after-fsync");
}
// Capture the intended write only as an external observation. The restarted
// node receives neither this file nor the injection environment.
static int cut_intent_write(int fd, const void *bytes, size_t count, ssize_t *result) {
    const char *point = getenv("RTOS_TEST_SOURCE_INTENT_POINT");
    const char *snapshot = getenv("RTOS_TEST_SOURCE_INTENT_INTENDED");
    if (!point || (strcmp(point, "before-write") && strcmp(point, "after-partial-write"))
        || !snapshot || !count || count > (16 << 20)) return 0;
    char path[PATH_MAX]; struct stat info;
    if (!selected_intent(fd, path, &info) || info.st_size != 0) return 0;
    int proof = open(snapshot, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (proof < 0) return 0;
    size_t copied = 0;
    while (copied < count) {
        ssize_t n = syscall(SYS_write, proof, (const char *)bytes + copied, count - copied);
        if (n <= 0) { close(proof); return 0; }
        copied += (size_t)n;
    }
    int synced = syscall(SYS_fsync, proof), closed = close(proof);
    if (synced || closed) return 0;
    if (!strcmp(point, "after-partial-write")) {
        if (count < 2) return 0;
        size_t half = count / 2;
        *result = syscall(SYS_write, fd, bytes, half);
        if (*result != (ssize_t)half) return 1;
        if (syscall(SYS_fsync, fd)) return 1;
        stop_intent_at(path, point);
        return 1;
    }
    stop_intent_at(path, point);
    return 0;
}
ssize_t write(int fd, const void *bytes, size_t count) {
    if (count && fail_once(fd, "write-enospc", ENOSPC)) return -1;
    ssize_t result;
    if (cut_intent_write(fd, bytes, count, &result)) return result;
    return syscall(SYS_write, fd, bytes, count);
}
int fsync(int fd) {
    if (fail_once(fd, "sync-eio", EIO)) return -1;
    int result = (int)syscall(SYS_fsync, fd);
    int saved_errno = errno;
    if (!result) stop_synced_intent(fd);
    errno = saved_errno;
    return result;
}
int fdatasync(int fd) {
    if (fail_once(fd, "sync-eio", EIO)) return -1;
    int result = (int)syscall(SYS_fdatasync, fd);
    int saved_errno = errno;
    if (!result) stop_synced_intent(fd);
    errno = saved_errno;
    return result;
}
