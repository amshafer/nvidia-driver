/*
 * Copyright (c) 2015, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "nvidia-drm.h"

#if defined(NV_DRM_AVAILABLE)

#include "nvidia-drm-priv.h"
#include "nvidia-drm-drv.h"

static struct NvKmsKapiFunctionsTable nvKmsFuncsTable = {
    .versionString = NV_VERSION_STRING,
};

const struct NvKmsKapiFunctionsTable* const nvKms = &nvKmsFuncsTable;

#endif

int nv_drm_init(void)
{
#if defined(NV_DRM_AVAILABLE)
    if (!nvKmsKapiGetFunctionsTable(&nvKmsFuncsTable)) {
        NV_DRM_LOG_ERR(
            "Version mismatch: nvidia-modeset.ko(%s) nvidia-drm.ko(%s)",
            nvKmsFuncsTable.versionString, NV_VERSION_STRING);
        return -EINVAL;
    }
#ifdef __linux__
	return nv_drm_probe_devices();
#else
/* pretty print nvKmsFuncsTable */
    NV_DRM_LOG_INFO("nvKms:--------------");
    NV_DRM_LOG_INFO("nvKms->enumerateGpus = %lx", (unsigned long)nvKms->enumerateGpus);

    /*
     * set the driver features here as the bsd probe func
     * can be called more than once. Also specify that we are
     * doing modesetting
     */
    nv_drm_modeset_module_param = true;
    nv_drm_update_drm_driver_features();

    /*
     * register our pci driver to add drm devices
     * We use our own probe function (nv_drm_bsd_probe)
     * instead of the linux one as the linux one assumes
     * a pci device list has already been created.
     */
    nv_drm_devclass = devclass_create("nvidia-drm");
    nv_drm_pci_driver.bsdclass = nv_drm_devclass;
    int ret = linux_pci_register_drm_driver(&nv_drm_pci_driver);
    NV_DRM_LOG_INFO("Registered pci driver with ret: %d", ret);
    
    return ret;
#endif /* __linux__ */
#endif /* NV_DRM_AVAILABLE */
}

void nv_drm_exit(void)
{
#if defined(NV_DRM_AVAILABLE)
    nv_drm_remove_devices();
#endif
}
