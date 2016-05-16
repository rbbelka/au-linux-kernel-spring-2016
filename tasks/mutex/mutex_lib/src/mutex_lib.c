#include <fcntl.h>

#include <mutex.h>
#include <mutex_ioctl.h>
#include <shared_spinlock.h>

int md_fd = -1;

mutex_err_t mutex_init(mutex_t *m)
{
    mutex_ioctl_lock_create_arg_t arg;
    
	shared_spinlock_init(&m->spinlock);
	m->kwaiters_cnt = 0;

	if (ioctl(md_fd, MUTEX_IOCTL_LOCK_CREATE, &arg) < 0)
		return MUTEX_INTERNAL_ERR;
    // saving received id to mutex	
    m->kid = arg.id;

	return MUTEX_OK;
}

mutex_err_t mutex_deinit(mutex_t *m)
{
	mutex_ioctl_lock_destroy_arg_t arg;
    // getting id from mutex
	arg.id = m->kid;
	if (ioctl(md_fd, MUTEX_IOCTL_LOCK_DESTROY, &arg) < 0)
		return MUTEX_INTERNAL_ERR;

	return MUTEX_OK;
}

mutex_err_t mutex_lock(mutex_t *m)
{
	mutex_ioctl_lock_wait_arg_t arg;
    // ok if immediately acquired
	if (shared_spin_trylock(&m->spinlock))
		return MUTEX_OK;

	arg.spinlock = &m->spinlock;
	arg.id = m->kid;

    //waiting if not acquired
	__sync_add_and_fetch(&m->kwaiters_cnt, 1);
	if (ioctl(md_fd, MUTEX_IOCTL_LOCK_WAIT, &arg) < 0) 
    {
		__sync_sub_and_fetch(&m->kwaiters_cnt, 1);
		return MUTEX_INTERNAL_ERR;
	}
	__sync_sub_and_fetch(&m->kwaiters_cnt, 1);

    return MUTEX_OK;
}

mutex_err_t mutex_unlock(mutex_t *m)
{
	mutex_ioctl_lock_wake_arg_t arg;
    // if queue is empty - just release
	if (m->kwaiters_cnt == 0) {
		if (shared_spin_unlock(&m->spinlock) == 0)
			return MUTEX_INTERNAL_ERR;
		return MUTEX_OK;
	}

	arg.spinlock = &m->spinlock;
	arg.id = m->kid;
    // if having waiters - waking one up
	if (ioctl(md_fd, MUTEX_IOCTL_LOCK_WAKE, &arg) < 0)
	    return MUTEX_INTERNAL_ERR;

	return MUTEX_OK;
}

mutex_err_t mutex_lib_init()
{
    // already initialized
	if (md_fd >= 0)
		return MUTEX_INTERNAL_ERR;
    // init
    md_fd = open("/dev/mutex", O_RDWR);
    // can't open
	if (md_fd < 0)
        return MUTEX_INTERNAL_ERR;
	return MUTEX_OK;
}

mutex_err_t mutex_lib_deinit()
{
    // wasn't initialized or already deinit
	if (md_fd == -1)
		return MUTEX_INTERNAL_ERR;
    // can't close
	if (close(md_fd) < 0)
		return MUTEX_INTERNAL_ERR;
    // deinit
	md_fd = -1;
    return MUTEX_OK;
}
