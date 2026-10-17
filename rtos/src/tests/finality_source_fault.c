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
