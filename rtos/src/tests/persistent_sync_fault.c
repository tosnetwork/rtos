// Test-only, one-shot EIO on the exact owned snapshot file or its parent.
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

static int sync_or_fail(int fd, long syscall_number) {
    const char *target = getenv("RTOS_TEST_PERSISTENT_TARGET");
    const char *phase = getenv("RTOS_TEST_PERSISTENT_PHASE");
    const char *marker = getenv("RTOS_TEST_PERSISTENT_MARKER");
    if (!target || !phase || !marker || target[0] != '/') return syscall(syscall_number, fd);
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, sizeof(path)-1);
    if (length <= 0) return syscall(syscall_number, fd);
    path[length] = 0;
    struct stat info;
    if (fstat(fd, &info)) return syscall(syscall_number, fd);
    size_t n = strlen(target);
    int selected = 0;
    if (!strcmp(phase, "file")) {
        const char *suffix = path + (strlen(path) >= n ? n : strlen(path));
        size_t k = strlen(suffix);
        selected = S_ISREG(info.st_mode) && info.st_size > 0 && !strncmp(path,target,n)
            && k >= 4 && suffix[0] == '.' && !strcmp(suffix+k-4,".tmp") && access(target,F_OK);
        if (selected && k > 4) {
            // Raw publication uses .<pid>.<counter>.tmp; other producers use .tmp.
            const char *s = suffix+1; size_t digits = strspn(s,"0123456789");
            selected = digits && s[digits]=='.';
            if (selected) { s += digits+1; digits=strspn(s,"0123456789"); selected=digits && !strcmp(s+digits,".tmp"); }
        }
    } else if (!strcmp(phase, "published")) {
        selected = S_ISREG(info.st_mode) && info.st_size > 0 && !strcmp(path,target);
    } else if (!strcmp(phase, "directory")) {
        const char *slash = strrchr(target,'/');
        struct stat published;
        selected = slash && S_ISDIR(info.st_mode) && (size_t)length==(size_t)(slash-target)
            && !strncmp(path,target,(size_t)length) && !stat(target,&published)
            && S_ISREG(published.st_mode) && published.st_size>0;
    }
    if (!selected) return syscall(syscall_number, fd);
    int proof = open(marker,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (proof < 0) { if (errno==EEXIST) return syscall(syscall_number,fd); return -1; }
    char message[PATH_MAX+64];
    int size = snprintf(message,sizeof(message),"%s sync EIO: %s\n",phase,path);
    ssize_t written=syscall(SYS_write,proof,message,(size_t)size);
    int synced=syscall(SYS_fsync,proof); int closed=close(proof);
    if (written!=size || synced || closed) { errno=EIO; return -1; }
    errno=EIO; return -1;
}
int fsync(int fd) { return sync_or_fail(fd,SYS_fsync); }
int fdatasync(int fd) { return sync_or_fail(fd,SYS_fdatasync); }

static int fail_rename(const char *from, const char *to) {
    const char *target=getenv("RTOS_TEST_PERSISTENT_TARGET");
    const char *phase=getenv("RTOS_TEST_PERSISTENT_PHASE");
    const char *marker=getenv("RTOS_TEST_PERSISTENT_MARKER");
    if (!target || !phase || !marker || strcmp(phase,"rename") || target[0]!='/' || strcmp(to,target)) return 0;
    size_t n=strlen(target), length=strlen(from);
    if (length < n+4 || strncmp(from,target,n) || from[n]!='.' || strcmp(from+length-4,".tmp")) return 0;
    struct stat info;
    if (stat(from,&info) || !S_ISREG(info.st_mode) || info.st_size<=0 || !access(target,F_OK)) return 0;
    int proof=open(marker,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (proof<0) { if (errno==EEXIST) return 0; return 1; }
    char message[PATH_MAX+64];
    int size=snprintf(message,sizeof(message),"rename EIO: %s\n",target);
    ssize_t written=syscall(SYS_write,proof,message,(size_t)size);
    int synced=syscall(SYS_fsync,proof);int closed=close(proof);
    if (written!=size || synced || closed) { errno=EIO;return 1; }
    errno=EIO;return 1;
}
int rename(const char *from, const char *to) {
    if (fail_rename(from,to)) return -1;
    return syscall(SYS_renameat,AT_FDCWD,from,AT_FDCWD,to);
}
int renameat(int from_fd, const char *from, int to_fd, const char *to) {
    if (from[0]=='/' && to[0]=='/' && fail_rename(from,to)) return -1;
    return syscall(SYS_renameat,from_fd,from,to_fd,to);
}
