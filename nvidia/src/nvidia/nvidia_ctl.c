/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2002 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-freebsd.h"

#ifdef NV_SUPPORT_LINUX_COMPAT
#include <compat/linux/linux_util.h>

const char nvidia_driver_name[] = "nvidia";
#endif

static d_open_t  nvidia_ctl_open;
static d_ioctl_t nvidia_ctl_ioctl;
static d_poll_t  nvidia_ctl_poll;
static d_mmap_single_t nvidia_ctl_mmap_single;

static struct cdevsw nvidia_ctl_cdevsw = {
    .d_open =      nvidia_ctl_open,
    .d_ioctl =     nvidia_ctl_ioctl,
    .d_poll =      nvidia_ctl_poll,
    .d_mmap_single = nvidia_ctl_mmap_single,
    .d_name =      "nvidiactl",
    .d_version =   D_VERSION,
};

static struct cdev *nvidia_ctl_cdev = NULL;
struct nvidia_softc nvidia_ctl_sc;

static int nvidia_count = 0;

static int nvidia_ctl_open(
    struct cdev *dev,
    int oflags,
    int devtype,
    struct thread *td
)
{
    int status;
    nv_state_t *nv = &nvidia_ctl_state;
    nv_freebsd_file_private_t *nvffp;

    nvffp = malloc(sizeof(nv_freebsd_file_private_t),
                   M_NVIDIA, (M_WAITOK | M_ZERO));
    if (nvffp == NULL)
        return ENOMEM;

    NV_UMA_ZONE_ALLOC_STACK(nvffp->fops_sp);
    if (nvffp->fops_sp == NULL) {
        free(nvffp, M_NVIDIA);
        return ENOMEM;
    }
    sx_init(&nvffp->fops_sx, "fops_sx");

    nvffp->nv = nv;
    mtx_init(&nvffp->event_mtx, "event_mtx", NULL, (MTX_DEF | MTX_RECURSE));
    STAILQ_INIT(&nvffp->event_queue);

    status = nvidia_open_ctl(nv, nvffp);

    if (status != 0) {
        mtx_destroy(&nvffp->event_mtx);
        sx_destroy(&nvffp->fops_sx);
        NV_UMA_ZONE_FREE_STACK(nvffp->fops_sp);
        free(nvffp, M_NVIDIA);
        return status;
    }

    status = devfs_set_cdevpriv(nvffp, nvidia_ctl_dtor);
    if (status != 0) {
        nvidia_close_ctl(nv, nvffp);
        mtx_destroy(&nvffp->event_mtx);
        sx_destroy(&nvffp->fops_sx);
        NV_UMA_ZONE_FREE_STACK(nvffp->fops_sp);
        free(nvffp, M_NVIDIA);
        return status;
    }

    return status;
}

void nvidia_ctl_dtor(void *arg)
{
    nv_freebsd_file_private_t *nvffp = arg;
    struct nvidia_event *et;
    nv_state_t *nv = nvffp->nv;

    nvidia_close_ctl(nv, nvffp);

    while ((et = STAILQ_FIRST(&nvffp->event_queue))) {
        STAILQ_REMOVE(&nvffp->event_queue, et, nvidia_event, queue);
        free(et, M_NVIDIA);
    }
    mtx_destroy(&nvffp->event_mtx);

    sx_destroy(&nvffp->fops_sx);
    NV_UMA_ZONE_FREE_STACK(nvffp->fops_sp);

    free(nvffp, M_NVIDIA);
}

static int nvidia_ctl_ioctl(
    struct cdev *dev,
    u_long cmd,
    caddr_t data,
    int fflag,
    struct thread *td
)
{
    int status;
    nv_state_t *nv = &nvidia_ctl_state;
    nv_freebsd_file_private_t *nvffp;

    status = devfs_get_cdevpriv((void **)&nvffp);
    if (status != 0)
        return status;

    if (__NV_IOC_TYPE(cmd) != NV_IOCTL_MAGIC)
        return ENOTTY;

    return nvidia_handle_ioctl(nv, nvffp, cmd, data);
}

static int nvidia_ctl_poll(
    struct cdev *dev,
    int events,
    struct thread *td
)
{
    nv_freebsd_file_private_t *nvffp;
    int status, mask = 0;

    status = devfs_get_cdevpriv((void **)&nvffp);
    if (status != 0)
        return 0;

    mtx_lock(&nvffp->event_mtx);

    if (STAILQ_EMPTY(&nvffp->event_queue) && !nvffp->event_pending)
        selrecord(td, &nvffp->event_rsel);
    else {
        mask = (events & (POLLIN | POLLPRI | POLLRDNORM));
        nvffp->event_pending = NV_FALSE;
    }

    mtx_unlock(&nvffp->event_mtx);

    return mask;
}

static int nvidia_ctl_mmap_single(
    struct cdev *dev,
    vm_ooffset_t *offset,
    vm_size_t size,
    vm_object_t *object,
    int nprot
)
{
    int status;
    nv_freebsd_file_private_t *nvffp;

    status = devfs_get_cdevpriv((void **)&nvffp);
    if (status != 0)
        return status;

    return nvidia_mmap_ctl_single(nvffp, offset, size, object, nprot);
}

int nvidia_ctl_attach(void)
{
#ifdef NV_SUPPORT_LINUX_COMPAT
    struct linux_device_handler nvidia_ctl_linux_handler = { 
        .bsd_driver_name = __DECONST(char *, nvidia_driver_name),
        .linux_driver_name = __DECONST(char *, nvidia_driver_name),
        .bsd_device_name = __DECONST(char *, nvidia_ctl_cdevsw.d_name),
        .linux_device_name = __DECONST(char *, nvidia_ctl_cdevsw.d_name),
        .linux_major = NV_MAJOR_DEVICE_NUMBER,
        .linux_minor = CDEV_CTL_MINOR,
        .linux_char_device = 1 
    };  
#endif

    if (nvidia_count == 0) {
        nvidia_ctl_cdev = make_dev(&nvidia_ctl_cdevsw,
                CDEV_CTL_MINOR,
                UID_ROOT, GID_WHEEL, 0666,
                "%s", nvidia_ctl_cdevsw.d_name);
        if (nvidia_ctl_cdev == NULL)
            return ENOMEM;

#ifdef NV_SUPPORT_LINUX_COMPAT
	linux_device_register_handler(&nvidia_ctl_linux_handler);
#endif
    }

    nvidia_count++;
    return 0;
}

int nvidia_ctl_detach(void)
{
#ifdef NV_SUPPORT_LINUX_COMPAT
    struct linux_device_handler nvidia_ctl_linux_handler = { 
        .bsd_driver_name = __DECONST(char *, nvidia_driver_name),
        .linux_driver_name = __DECONST(char *, nvidia_driver_name),
        .bsd_device_name = __DECONST(char *, nvidia_ctl_cdevsw.d_name),
        .linux_device_name = __DECONST(char *, nvidia_ctl_cdevsw.d_name),
        .linux_major = NV_MAJOR_DEVICE_NUMBER,
        .linux_minor = CDEV_CTL_MINOR,
        .linux_char_device = 1 
    };  
#endif

    nvidia_count--;

    if (nvidia_count == 0) {
#ifdef NV_SUPPORT_LINUX_COMPAT
        linux_device_unregister_handler(&nvidia_ctl_linux_handler);
#endif	
        destroy_dev(nvidia_ctl_cdev);
    }

    return 0;
}
