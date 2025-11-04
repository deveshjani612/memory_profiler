#include <sys/mman.h>
#include <unistd.h>

int main() {
    for (int i = 0; i < 20; i++) {
        void *p = mmap(NULL, 4096 * 100, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ((char*)p)[0] = 1;
        usleep(500000);
        munmap(p, 4096 * 100);
    }
    return 0;
}

