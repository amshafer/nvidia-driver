/*
 * Copyright 2015 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 */

#ifndef __NV_KMS_H__
#define __NV_KMS_H__

#include "nvtypes.h"
#include <stddef.h> /* size_t */

#include "nvkms-kapi.h"

typedef struct nvkms_per_open nvkms_per_open_handle_t;

typedef void nvkms_procfs_out_string_func_t(void *data,
                                            const char *str);

typedef void nvkms_procfs_proc_t(void *data,
                                 char *buffer, size_t size,
                                 nvkms_procfs_out_string_func_t *outString);

typedef struct {
    const char *name;
    nvkms_procfs_proc_t *func;
} nvkms_procfs_file_t;

enum NvKmsClientType {
    NVKMS_CLIENT_USER_SPACE,
    NVKMS_CLIENT_KERNEL_SPACE,
};

NvBool nvKmsIoctl(
    void *pOpenVoid,
    NvU32 cmd,
    NvU64 paramsAddress,
    const size_t paramSize);

void nvKmsClose(void *pOpenVoid);

void* nvKmsOpen(
    NvU32 pid,
    enum NvKmsClientType clientType,
    nvkms_per_open_handle_t *pOpenKernel);

NvBool nvKmsModuleLoad(void);

void nvKmsModuleUnload(void);

void nvKmsSuspend(NvU32 gpuId);
void nvKmsResume(NvU32 gpuId);

void nvKmsGetProcFiles(const nvkms_procfs_file_t **ppProcFiles);

void nvKmsKapiHandleEventQueueChange
(
    struct NvKmsKapiDevice *device
);

NvBool nvKmsKapiGetFunctionsTableInternal
(
    struct NvKmsKapiFunctionsTable *funcsTable
);

NvBool nvKmsGetBacklight(NvU32 display_id, void *drv_priv, NvU32 *brightness);
NvBool nvKmsSetBacklight(NvU32 display_id, void *drv_priv, NvU32 brightness);

#endif /* __NV_KMS_H__ */
