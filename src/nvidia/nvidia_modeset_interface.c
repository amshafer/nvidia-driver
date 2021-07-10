/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2015 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "nv-modeset-interface.h"

#include "os-interface.h"
#include "nvstatus.h"
#include "nv.h"
#include "nv-freebsd.h"

static const nvidia_modeset_callbacks_t *nv_modeset_callbacks;

static int nvidia_modeset_rm_ops_alloc_stack(nvidia_stack_t **sp)
{
    NV_UMA_ZONE_ALLOC_STACK(*sp);
    return (*sp == NULL) ? ENOMEM : 0;
}

static void nvidia_modeset_rm_ops_free_stack(nvidia_stack_t *sp)
{
    NV_UMA_ZONE_FREE_STACK(sp);
}

static int nvidia_modeset_set_callbacks(const nvidia_modeset_callbacks_t *cb)
{
    if ((nv_modeset_callbacks != NULL && cb != NULL) ||
        (nv_modeset_callbacks == NULL && cb == NULL))
    {
        return -EINVAL;
    }

    nv_modeset_callbacks = cb;
    return 0;
}

void nvidia_modeset_suspend(NvU32 gpuId)
{
    if (nv_modeset_callbacks)
    {
        nv_modeset_callbacks->suspend(gpuId);
    }
}

void nvidia_modeset_resume(NvU32 gpuId)
{
    if (nv_modeset_callbacks)
    {
        nv_modeset_callbacks->resume(gpuId);
    }
}

NV_STATUS nvidia_get_rm_ops(nvidia_modeset_rm_ops_t *rm_ops)
{
    const nvidia_modeset_rm_ops_t local_rm_ops = {
        .version_string = NV_VERSION_STRING,
        .system_info    = {
            .allow_write_combining = NV_FALSE,
        },
        .alloc_stack    = nvidia_modeset_rm_ops_alloc_stack,
        .free_stack     = nvidia_modeset_rm_ops_free_stack,
        .enumerate_gpus = NULL,
        .open_gpu       = nvidia_open_dev_kernel,
        .close_gpu      = nvidia_close_dev_kernel,
        .op             = rm_kernel_rmapi_op, /* provided by nv-kernel.o */
        .set_callbacks  = nvidia_modeset_set_callbacks,
    };

    if (strcmp(rm_ops->version_string, NV_VERSION_STRING) != 0)
    {
        rm_ops->version_string = NV_VERSION_STRING;
        return NV_ERR_GENERIC;
    }

    *rm_ops = local_rm_ops;

    return NV_OK;
}


