#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include "vsd_device.h"
#include "../vsd_driver/vsd_ioctl.h"

static int dev;

int vsd_init()
{
    dev = open("/dev/vsd", O_RDWR);
    return dev == -1 ? EXIT_FAILURE : EXIT_SUCCESS;;
}

int vsd_deinit()
{
    return close(dev);
}

int vsd_get_size(size_t *out_size)
{
    vsd_ioctl_get_size_arg_t get_size;
    if (ioctl(dev, VSD_IOCTL_GET_SIZE, &get_size) == -1)
        return EXIT_FAILURE;

    *out_size = get_size.size;
    return EXIT_SUCCESS;
}

int vsd_set_size(size_t size)
{
    vsd_ioctl_set_size_arg_t set_size;
    set_size.size = size;
    return ioctl(dev, VSD_IOCTL_SET_SIZE, &set_size) == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}

//кажется, что читать должны из src, а писать в dst.

ssize_t vsd_read(char* src, off_t offset, size_t size)
{
    if (lseek(dev, offset, SEEK_SET) == -1)
        return EXIT_FAILURE;

    return read(dev, src, size);
}

ssize_t vsd_write(const char* dst, off_t offset, size_t size)
{
    if (lseek(dev, offset, SEEK_SET) == -1)
        return EXIT_FAILURE;

    return read(dev, dst, size);
}

void* vsd_mmap(size_t offset)
{
    size_t size = 0;
    vsd_get_size(&size);
    return mmap(NULL, size - offset, PROT_READ | PROT_WRITE, MAP_SHARED, dev, offset);
}

int vsd_munmap(void* addr, size_t offset)
{
    size_t size = 0;
    vsd_get_size(&size);
    return munmap(addr, size - offset);
}

