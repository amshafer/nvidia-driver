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

static d_open_t  nvidia_dev_open;
static d_ioctl_t nvidia_dev_ioctl;
static d_poll_t  nvidia_dev_poll;
static d_mmap_single_t nvidia_dev_mmap_single;

#ifdef NV_SUPPORT_LINUX_COMPAT
#include <compat/linux/linux_util.h>
#endif

static struct cdevsw nvidia_dev_cdevsw = {
    .d_open =      nvidia_dev_open,
    .d_ioctl =     nvidia_dev_ioctl,
    .d_poll =      nvidia_dev_poll,
    .d_mmap_single = nvidia_dev_mmap_single,
    .d_name =      "nvidia",
    .d_version =   D_VERSION,
    .d_flags =     D_MEM
};

static int nvidia_dev_open(
    struct cdev *dev,
    int oflags,
    int devtype,
    struct thread *td
)
{
    int status;
    struct nvidia_softc *sc = dev->si_drv1;
    nv_state_t *nv = sc->nv_state;
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

    status = nvidia_open_dev(nv, nvffp);

    if (status != 0) {
        mtx_destroy(&nvffp->event_mtx);
        sx_destroy(&nvffp->fops_sx);
        NV_UMA_ZONE_FREE_STACK(nvffp->fops_sp);
        free(nvffp, M_NVIDIA);
        return status;
    }

    status = devfs_set_cdevpriv(nvffp, nvidia_dev_dtor);
    if (status != 0) {
        nvidia_close_dev(nv, nvffp);
        mtx_destroy(&nvffp->event_mtx);
        sx_destroy(&nvffp->fops_sx);
        NV_UMA_ZONE_FREE_STACK(nvffp->fops_sp);
        free(nvffp, M_NVIDIA);
        return status;
    }

    return 0;
}

void nvidia_dev_dtor(void *arg)
{
    nv_freebsd_file_private_t *nvffp = arg;
    struct nvidia_event *et;
    nv_state_t *nv = nvffp->nv;

    nvidia_close_dev(nv, nvffp);

    while ((et = STAILQ_FIRST(&nvffp->event_queue))) {
        STAILQ_REMOVE(&nvffp->event_queue, et, nvidia_event, queue);
        free(et, M_NVIDIA);
    }
    mtx_destroy(&nvffp->event_mtx);

    sx_destroy(&nvffp->fops_sx);
    NV_UMA_ZONE_FREE_STACK(nvffp->fops_sp);

    free(nvffp, M_NVIDIA);
}

static int nvidia_dev_ioctl(
    struct cdev *dev,
    u_long cmd,
    caddr_t data,
    int fflag,
    struct thread *td
)
{
    int status;
    nv_freebsd_file_private_t *nvffp;
    nv_state_t *nv;

    status = devfs_get_cdevpriv((void **)&nvffp);
    if (status != 0)
        return status;
    nv = nvffp->nv;

    if (__NV_IOC_TYPE(cmd) != NV_IOCTL_MAGIC)
        return ENOTTY;

    return nvidia_handle_ioctl(nv, nvffp, cmd, data);
}

static int nvidia_dev_poll(
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

static int nvidia_dev_mmap_single(
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

    return nvidia_mmap_dev_single(nvffp, offset, size, object, nprot);
}

int nvidia_dev_attach(struct nvidia_softc *sc)
{
#ifdef NV_SUPPORT_LINUX_COMPAT
    struct linux_device_handler nvidia_dev_linux_handler = {
        .bsd_driver_name = __DECONST(char *, nvidia_driver_name),
        .linux_driver_name = __DECONST(char *, nvidia_driver_name),
        .bsd_device_name = NULL,
        .linux_device_name = NULL,
        .linux_major = NV_MAJOR_DEVICE_NUMBER,
        .linux_minor = device_get_unit(sc->dev),
        .linux_char_device = 1
    };
#endif

    sc->cdev = make_dev(&nvidia_dev_cdevsw,
            device_get_unit(sc->dev),
            UID_ROOT, GID_WHEEL, 0666,
            "%s%d", nvidia_dev_cdevsw.d_name,
            device_get_unit(sc->dev));
    if (sc->cdev == NULL)
        return ENOMEM;

    sc->cdev->si_drv1 = sc;

#ifdef NV_SUPPORT_LINUX_COMPAT
    nvidia_dev_linux_handler.bsd_device_name = sc->cdev->si_name;
    nvidia_dev_linux_handler.linux_device_name = sc->cdev->si_name;
    (void)linux_device_register_handler(&nvidia_dev_linux_handler);
#endif    

    return 0;
}

int nvidia_dev_detach(struct nvidia_softc *sc)
{
#ifdef NV_SUPPORT_LINUX_COMPAT
    struct linux_device_handler nvidia_dev_linux_handler = {
        .bsd_driver_name = __DECONST(char *, nvidia_driver_name),
        .linux_driver_name = __DECONST(char *, nvidia_driver_name),
        .bsd_device_name = sc->cdev->si_name,
        .linux_device_name = sc->cdev->si_name,
        .linux_major = NV_MAJOR_DEVICE_NUMBER,
        .linux_minor = device_get_unit(sc->dev),
        .linux_char_device = 1
    };

    (void)linux_device_unregister_handler(&nvidia_dev_linux_handler);
#endif

    destroy_dev(sc->cdev);
    return 0;
}
