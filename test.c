/* test.c – verify wd_dma ioctls with clear PASS / FAIL output */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/memfd.h>

/* ioctl numbers (mirror wd_dma.c) */
#define WD_IOC_GET_COHERENT  0
#define WD_IOC_MAP_HUGEPAGE  1
#define WD_IOC_PASSTHROUGH   2

#ifndef MAP_HUGE_SHIFT            /* for older glibc headers */
#define MAP_HUGE_SHIFT 26
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB   (21 << MAP_HUGE_SHIFT)   /* 2 MiB */
#endif
#ifndef MFD_HUGE_2MB
#define MFD_HUGE_2MB   (21 << MFD_HUGE_SHIFT)
#endif

#define HUGEPAGE_SZ (2 * 1024 * 1024)

/* ----------------------------------------------------------------------------
 * helper: allocate a single 2 MiB hugetlb page via memfd + mmap
 * returns pointer or NULL on error
 * --------------------------------------------------------------------------*/
static void *alloc_hugetlb_2m(void)
{
    int fd = syscall(SYS_memfd_create, "wd_dma_hp",
                     MFD_CLOEXEC | MFD_HUGETLB | MFD_HUGE_2MB);
    if (fd < 0) { perror("memfd_create"); return NULL; }

    if (ftruncate(fd, HUGEPAGE_SZ)) { perror("ftruncate"); return NULL; }

    void *addr = mmap(NULL, HUGEPAGE_SZ,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) { perror("mmap"); return NULL; }

    /* keep fd open so the mapping remains valid */
    return addr;
}

/* ----------------------------------------------------------------------------
 * Test 1: built-in 4 MiB coherent buffer
 * --------------------------------------------------------------------------*/
static int test_coherent(int dev)
{
    uint64_t iova = 0;
    if (ioctl(dev, WD_IOC_GET_COHERENT, &iova)) {
        perror("WD_IOC_GET_COHERENT");
        printf("coherent buffer: FAIL\n");
        return -1;
    }
    printf("coherent buffer: PASS (IOVA 0x%llx)\n",
           (unsigned long long)iova);
    return 0;
}

/* ----------------------------------------------------------------------------
 * Test 2: map one hugetlb page
 * --------------------------------------------------------------------------*/
static int test_hugepage(int dev)
{
    void *hp = alloc_hugetlb_2m();
    if (!hp) { printf("hugepage alloc: FAIL\n"); return -1; }

    /* driver overwrites with IOVA */
    uint64_t arg = (uint64_t)hp;
    if (ioctl(dev, WD_IOC_MAP_HUGEPAGE, &arg)) {
        perror("WD_IOC_MAP_HUGEPAGE");
        printf("MAP_HUGEPAGE: FAIL\n");
        munmap(hp, HUGEPAGE_SZ);
        return -1;
    }

    printf("map hugepage: PASS (vaddr %p -> IOVA 0x%llx)\n",
           hp, (unsigned long long)arg);
    munmap(hp, HUGEPAGE_SZ);
    return 0;
}

/* ----------------------------------------------------------------------------
 * Test 3: passthrough – expect same address back unchanged
 * --------------------------------------------------------------------------*/
static int test_passthrough(int dev)
{
    /* allocate one regular page (anonymous) */
    void *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap anon"); return -1; }

    uint64_t orig = (uint64_t)buf;
    uint64_t arg  = orig;

    if (ioctl(dev, WD_IOC_PASSTHROUGH, &arg)) {
        perror("WD_IOC_PASSTHROUGH");
        printf("PASSTHROUGH: FAIL\n");
        munmap(buf, 4096);
        return -1;
    }

    if (arg != orig) {
        printf("PASSTHROUGH: FAIL (expected 0x%llx, got 0x%llx)\n",
               (unsigned long long)orig, (unsigned long long)arg);
        munmap(buf, 4096);
        return -1;
    }

    printf("passthrough: PASS (addr %p returned unchanged)\n", buf);
    munmap(buf, 4096);
    return 0;
}

/* ----------------------------------------------------------------------------
 * main – run all tests and summarise
 * --------------------------------------------------------------------------*/
int main(void)
{
    int dev = open("/dev/wd_dma", O_RDWR);
    if (dev < 0) { perror("open /dev/wd_dma"); return 1; }

    int fails = 0;
    fails += test_coherent(dev);
    fails += test_hugepage(dev);
    fails += test_passthrough(dev);

    close(dev);

    printf("status: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
