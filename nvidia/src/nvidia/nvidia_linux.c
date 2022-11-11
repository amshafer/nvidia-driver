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

#define LINUX_IOCTL_NVIDIA_MIN 0x4600
#define LINUX_IOCTL_NVIDIA_MAX 0x46ff

#if defined(NVCPU_X86_64)
#include "machine/../linux32/linux.h"
#include "machine/../linux32/linux32_proto.h"
#endif

#include <compat/linux/linux_ioctl.h>

int linux_ioctl_nvidia(struct thread *, struct linux_ioctl_args *);

int linux_ioctl_nvidia(
    struct thread *td,
    struct linux_ioctl_args *args
)
{
    uint32_t dir;

    /*
     * Linux allocates 14 bits for the parameter size, whereas FreeBSD only
     * allocates 13. Check for and reject commands with size fields that
     * encroach on the direction field.
     */
    if ((args->cmd & LINUX_IOC_INOUT) != (args->cmd & IOC_DIRMASK))
        return EINVAL;

    switch (args->cmd & LINUX_IOC_INOUT) {
        case LINUX_IOC_IN:
            dir = IOC_IN;
            break;
        case LINUX_IOC_OUT:
            dir = IOC_OUT;
            break;
        case LINUX_IOC_INOUT:
            dir = IOC_INOUT;
            break;
    }

    args->cmd = (args->cmd & ~LINUX_IOC_INOUT) | dir;

    return sys_ioctl(td, (struct ioctl_args *)args);
}

struct linux_ioctl_handler nvidia_handler = {
    linux_ioctl_nvidia,
    LINUX_IOCTL_NVIDIA_MIN,
    LINUX_IOCTL_NVIDIA_MAX
};
#endif /* NV_SUPPORT_LINUX_COMPAT */


void nvidia_linux_init(void)
{
#ifdef NV_SUPPORT_LINUX_COMPAT /* (COMPAT_LINUX || COMPAT_LINUX32) */
    linux_ioctl_register_handler(&nvidia_handler);
#endif
}

void nvidia_linux_exit(void)
{
#ifdef NV_SUPPORT_LINUX_COMPAT /* (COMPAT_LINUX || COMPAT_LINUX32) */
    linux_ioctl_unregister_handler(&nvidia_handler);
#endif
}
