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

#ifdef NV_SUPPORT_LINUX_COMPAT /* (COMPAT_LINUX || COMPAT_LINUX32) */

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
    struct file *fp;
    int error;
    cap_rights_t rights;
    u_long cmd;

    error = fget(td, args->fd, cap_rights_init(&rights, CAP_IOCTL), &fp);
    if (error != 0)
        return error;

    cmd = args->cmd;

    error = fo_ioctl(fp, cmd, (caddr_t)args->arg, td->td_ucred, td);
    fdrop(fp, td);

    return error;
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
