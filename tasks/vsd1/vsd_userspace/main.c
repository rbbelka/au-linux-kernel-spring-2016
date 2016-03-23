#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "../vsd_driver/vsd_ioctl.h"

int usage_failure () {
    printf("Use with argumets: \n size_set SIZE_IN_BYTES \n size_get \n");
    return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        return usage_failure();
    }

    int f = open("/dev/vsd", O_RDWR);
    if(f == -1) {
        printf("Device is not found \n");
        return EXIT_FAILURE;
    }

    if (argc == 2 && strcmp(argv[1], "size_get") == 0) {
        vsd_ioctl_get_size_arg_t size;
 
        int res = ioctl(f, VSD_IOCTL_GET_SIZE, &size);
        if (res != 0) {
            printf("ioctl error %d \n", res);
            return EXIT_FAILURE;
        }
        printf("vsd size: %d \n", (int)size.size);
        return EXIT_SUCCESS;
    }

    if (argc == 3 && strcmp(argv[1], "size_set") == 0) { 
        vsd_ioctl_set_size_arg_t size;
        size.size = atoi(argv[2]);
 
        int res = ioctl(f, VSD_IOCTL_SET_SIZE, &size);
        if (res != 0) {
            printf("ioctl error %d \n", res);
            return EXIT_FAILURE;
        }
        printf("vsd size changed to: %d \n", (int)size.size);
        return EXIT_SUCCESS;
    }

    return usage_failure();
}

