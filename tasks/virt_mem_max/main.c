#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>


int main()
{
    size_t size = -1;
    size_t mem_max = 0;

    while (size > 0) {
        char* res = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if (res != (char*) -1)
            mem_max += size;
        size /= 2;
    }
    
    printf("Max size = %zu\n", mem_max);
    return 0;
}
