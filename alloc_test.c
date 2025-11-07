#include <sys/mman.h>
#include <unistd.h>

int main() {
    for (int i = 0; i < 20; i++) {
        void *p = mmap(NULL, 4096 * 100, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ((char*)p)[0] = 1;
        ((char*)p)[4096] = 1;
        ((char*)p)[4096*2] = 1;
        ((char*)p)[4096*3] = 1;
        ((char*)p)[4096*4] = 1;
        sleep(2);
        munmap(p, 4096 * 100);
    }
    return 0;
}
