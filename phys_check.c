#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>

uint64_t get_physical_address(uint64_t virtual_addr) {
    uint64_t value;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open pagemap");
        return 0;
    }
    lseek(fd, (virtual_addr / 4096) * 8, SEEK_SET);
    read(fd, &value, 8);
    close(fd);

    if (!(value & (1ULL << 63)))    // Present bit
        return 0;

    uint64_t pfn = value & ((1ULL << 55) - 1);
    return pfn;
}

int main() {
    const int num_pages = 100;
    size_t size = num_pages * 4096;
    char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Touch pages to force page faults
    for (int i = 0; i < num_pages; i++) {
        p[i * 4096] = 1;
    }

    printf("Page\tVirtual Address\tPFN\tPhysical Address (approx)\n");
    for (int i = 0; i < num_pages; i++) {
        uint64_t vaddr = (uint64_t)(p + i * 4096);
        uint64_t pfn = get_physical_address(vaddr);
        if (pfn)
            printf("%d\t%p\t%llu\t0x%llx\n", i, (void*)vaddr, pfn, pfn * 4096);
        else
            printf("%d\t%p\tNot present\n", i, (void*)vaddr);
    }

    munmap(p, size);
    return 0;
}


