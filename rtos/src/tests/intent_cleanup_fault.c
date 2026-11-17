// Isolated fixture: retain one accepted intent/output set with a real EIO.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char selected[PATH_MAX];

static int copy_owned(const char *source, const char *target, size_t bound) {
  int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (input < 0)
    return -1;
  struct stat st;
  if (fstat(input, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      (unsigned long long)st.st_size > bound) {
    close(input);
    return -1;
  }
  int output =
      open(target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (output < 0) {
    close(input);
    return -1;
  }
  char bytes[8192];
  ssize_t count;
  int ok = 1;
  while ((count = read(input, bytes, sizeof(bytes))) > 0) {
    ssize_t pos = 0;
    while (pos < count) {
      ssize_t written = write(output, bytes + pos, (size_t)(count - pos));
      if (written <= 0) {
        ok = 0;
        break;
      }
      pos += written;
    }
    if (!ok)
      break;
  }
  if (count < 0 || fsync(output))
    ok = 0;
  close(input);
  if (close(output))
    ok = 0;
  return ok ? 0 : -1;
}

static int reject(const char *path) {
  const char *control = getenv("RTOS_TEST_INTENT_CLEANUP_CONTROL");
  if (!control || control[0] != '/')
    return 0;
  struct stat original_info;
  if (lstat(path, &original_info) || !S_ISREG(original_info.st_mode))
    return 0;
  char resolved[PATH_MAX], config[PATH_MAX];
  if (!realpath(path, resolved))
    return 0;
  if (snprintf(config, sizeof(config), "%s/selector", control) >=
      (int)sizeof(config))
    return 0;
  int fd = open(config, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  char data[PATH_MAX + 64];
  ssize_t size = read(fd, data, sizeof(data) - 1);
  close(fd);
  if (size <= 0 || size == (ssize_t)sizeof(data) - 1)
    return 0;
  data[size] = 0;
  long pid;
  char directory[PATH_MAX];
  if (sscanf(data, "%ld\n%4095[^\n]", &pid, directory) != 2 || pid != getpid())
    return 0;
  size_t prefix = strlen(directory);
  if (strncmp(resolved, directory, prefix) || resolved[prefix] != '/')
    return 0;
  const char *name = resolved + prefix + 1;
  const char *dash = strchr(name, '-');
  if (!dash || dash == name)
    return 0;
  for (const char *p = name; p < dash; ++p)
    if (*p < '0' || *p > '9')
      return 0;
  if (strlen(dash + 1) != 64 + strlen(".outputs"))
    return 0;
  for (int i = 1; i <= 64; ++i)
    if (!((dash[i] >= '0' && dash[i] <= '9') ||
          (dash[i] >= 'a' && dash[i] <= 'f')))
      return 0;
  if (strcmp(dash + 65, ".outputs"))
    return 0;
  pthread_mutex_lock(&lock);
  int match = 0;
  if (!selected[0]) {
    // The store's mutation lock spans this unlink. Capture before deletion;
    // neither a snapshot nor this selector is ever input to node recovery.
    char pending[PATH_MAX], output_copy[PATH_MAX], intent_copy[PATH_MAX],
        receipt[PATH_MAX];
    char parent[PATH_MAX];
    snprintf(parent, sizeof(parent), "%s", directory);
    char *last = strrchr(parent, '/');
    if (!last || strcmp(last, "/outputs-v1"))
      goto done;
    *last = 0;
    int stem = (int)(strlen(name) - strlen(".outputs"));
    if (snprintf(pending, sizeof(pending), "%s/%.*s.json", parent, stem,
                 name) >= (int)sizeof(pending) ||
        snprintf(output_copy, sizeof(output_copy), "%s/original.outputs",
                 control) >= (int)sizeof(output_copy) ||
        snprintf(intent_copy, sizeof(intent_copy), "%s/original.json",
                 control) >= (int)sizeof(intent_copy) ||
        snprintf(receipt, sizeof(receipt), "%s/captured", control) >=
            (int)sizeof(receipt))
      goto done;
    struct stat st;
    if (lstat(resolved, &st) || !S_ISREG(st.st_mode))
      goto done;
    // Claim this exact target even if saving evidence fails. The driver must
    // reject missing/incomplete evidence; never accidentally delete it.
    snprintf(selected, sizeof(selected), "%s", resolved);
    match = 1;
    if (copy_owned(resolved, output_copy, 256 << 10) ||
        copy_owned(pending, intent_copy, 16 << 20))
      goto done;
    FILE *file = fopen(receipt, "wx");
    if (!file)
      goto done;
    fprintf(file, "%ld\n%llu\n%llu\n%s\n%s\n", (long)getpid(),
            (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
            resolved, pending);
    if (!fflush(file))
      fsync(fileno(file));
    fclose(file);
    int dir = open(control, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir >= 0) {
      fsync(dir);
      close(dir);
    }
  } else {
    match = strcmp(selected, resolved) == 0;
  }
done:
  pthread_mutex_unlock(&lock);
  return match;
}

int unlink(const char *path) {
  if (reject(path)) {
    errno = EIO;
    return -1;
  }
  int (*original)(const char *) = dlsym(RTLD_NEXT, "unlink");
  if (!original) {
    errno = ENOSYS;
    return -1;
  }
  return original(path);
}

int unlinkat(int dirfd, const char *path, int flags) {
  // Rust remove_file currently uses unlink. Cover absolute unlinkat calls as
  // well, without guessing the identity of relative dirfd paths.
  if (!flags && path[0] == '/' && reject(path)) {
    errno = EIO;
    return -1;
  }
  int (*original)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
  if (!original) {
    errno = ENOSYS;
    return -1;
  }
  return original(dirfd, path, flags);
}
