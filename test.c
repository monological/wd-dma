#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <unistd.h>

int main(void) {
    int fd = open("/dev/wd_dma", O_RDWR);
    uint64_t addr;
    ioctl(fd, 0, &addr);
    printf("FPGA should use IOVA 0x%llx\n", (unsigned long long)addr);
    close(fd);
    return 0;
}
