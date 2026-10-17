// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Fixture-only tagging. Packet handling stays in the isolated kernel network stack.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int socket(int domain, int type, int protocol) {
    int (*original)(int, int, int) = dlsym(RTLD_NEXT, "socket");
    if (!original) { errno = ENOSYS; return -1; }
    int fd = original(domain, type, protocol);
    const char *text = getenv("RTOS_FIXTURE_SOCKET_MARK");
    if (fd < 0 || !text || (domain != AF_INET && domain != AF_INET6)
        || ((type & 15) != SOCK_STREAM && (type & 15) != SOCK_DGRAM)) return fd;
    char netns[128], userns[128];
    const char *parent = getenv("RTOS_FIXTURE_PARENT_NETNS");
    const char *parent_user = getenv("RTOS_FIXTURE_PARENT_USERNS");
    ssize_t netlen = readlink("/proc/self/ns/net", netns, sizeof(netns)-1);
    ssize_t userlen = readlink("/proc/self/ns/user", userns, sizeof(userns)-1);
    if (!parent || !parent_user || netlen < 0 || userlen < 0 || geteuid() != 0) {
        close(fd); errno = EPERM; return -1;
    }
    netns[netlen] = 0; userns[userlen] = 0;
    if (!strcmp(parent, netns) || !strcmp(parent_user, userns)) {
        close(fd); errno = EPERM; return -1;
    }
    char *end;
    unsigned long value = strtoul(text, &end, 0);
    if (!*text || *end || !value || value > 0xffffffffUL) {
        close(fd); errno = EINVAL; return -1;
    }
    unsigned int mark = value;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        int error = errno; close(fd); errno = error; return -1;
    }
    return fd;
}
