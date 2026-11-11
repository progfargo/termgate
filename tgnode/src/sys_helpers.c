/* C helpers for libc structs that do not translate to Zig on every target.
 * musl's struct statvfs comes out opaque, so disk space is read here. */
#include <sys/statvfs.h>

int tgnode_disk_space(const char *path, unsigned long long *total, unsigned long long *avail)
{
    struct statvfs v;
    if (statvfs(path, &v) != 0) return -1;
    *total = (unsigned long long)v.f_blocks * v.f_frsize;
    *avail = (unsigned long long)v.f_bavail * v.f_frsize;
    return 0;
}
