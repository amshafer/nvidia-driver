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

/*
 * include the FreeBSD structures (nvidia_softc)
 * have to grab it from src/nvidia/nv-freebsd.h
 *
 * have to be done first before the LIST_HEAD linux version
 */
#include "nvmisc.h"
#define NVRM
#include "../nvidia/nv.h"
#include "../nvidia/nv-freebsd.h"

/* undef BIT, since it was just identically defined in nvmisc.h */
#undef BIT
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>

#include "../nvidia/os-interface.h"

#include "nvidia-drm-os-interface.h"
#include "nvidia-drm.h"

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_AVAILABLE)

#include "nv-mm.h"

#include "nv-gpu-info.h"
#include "nvidia-drm-drv.h"
#include "nvidia-drm-priv.h"

bool nv_drm_modeset_module_param = true;

SYSCTL_NODE(_hw, OID_AUTO, nvidiadrm, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "nvidia-drm kernel module parameters");
SYSCTL_BOOL(_hw_nvidiadrm, OID_AUTO, modeset,  CTLFLAG_RD | CTLFLAG_MPSAFE,
    &nv_drm_modeset_module_param,  1,
    "Enable atomic kernel modesetting (1 = enable, 0 = disable (default))");

void *nv_drm_calloc(size_t nmemb, size_t size)
{
    return kzalloc(nmemb * size, GFP_KERNEL);
}

void nv_drm_free(void *ptr)
{
    if (IS_ERR(ptr)) {
        return;
    }

    kfree(ptr);
}

char *nv_drm_asprintf(const char *fmt, ...)
{
    va_list ap;
    char *p;

    va_start(ap, fmt);
    p = kvasprintf(GFP_KERNEL, fmt, ap);
    va_end(ap);

    return p;
}

#if defined(NVCPU_X86) || defined(NVCPU_X86_64)
  #define WRITE_COMBINE_FLUSH()    sfence()
#elif defined(NVCPU_FAMILY_ARM)
  #if defined(NVCPU_ARM)
    #define WRITE_COMBINE_FLUSH()  { dsb(); outer_sync(); }
  #elif defined(NVCPU_AARCH64)
    #define WRITE_COMBINE_FLUSH()  mb()
  #endif
#elif defined(NVCPU_PPC64LE)
  /* should include powerpc_sync for a cleaner approach */
  #define WRITE_COMBINE_FLUSH()    __asm __volatile("sync":::"memory")
#endif

void nv_drm_write_combine_flush(void)
{
    WRITE_COMBINE_FLUSH();
}

int nv_drm_lock_user_pages(unsigned long address,
                           unsigned long pages_count, struct page ***pages)
{
    struct mm_struct *mm = current->mm;
    struct page **user_pages;
    const int write = 1;
    int pages_pinned;

    user_pages = nv_drm_calloc(pages_count, sizeof(*user_pages));

    if (user_pages == NULL) {
        return -ENOMEM;
    }

    down_read(&mm->mmap_sem);

    pages_pinned = NV_GET_USER_PAGES(address, pages_count, write,
                                     user_pages, NULL);
    up_read(&mm->mmap_sem);

    if (pages_pinned < 0 || (unsigned)pages_pinned < pages_count) {
        goto failed;
    }

    *pages = user_pages;

    return 0;

failed:

    if (pages_pinned > 0) {
        int i;

        for (i = 0; i < pages_pinned; i++) {
            put_page(user_pages[i]);
        }
    }

    nv_drm_free(user_pages);

    return (pages_pinned < 0) ? pages_pinned : -EINVAL;
}

void nv_drm_unlock_user_pages(unsigned long  pages_count, struct page **pages)
{
    unsigned long i;

    for (i = 0; i < pages_count; i++) {
        set_page_dirty_lock(pages[i]);

        put_page(pages[i]);
    }

    nv_drm_free(pages);
}

void *nv_drm_vmap(struct page **pages, unsigned long pages_count)
{
    return vmap(pages, pages_count, VM_USERMAP, PAGE_KERNEL);
}

void nv_drm_vunmap(void *address)
{
    vunmap(address);
}

uint64_t nv_drm_get_time_usec(void)
{
    struct timeval tv;

    microtime(&tv);

    return (((uint64_t)tv.tv_sec) * 1000000) + tv.tv_usec;
}

/*************************************************************************
 * FreeBSD linuxkpi based loading support code.
 *************************************************************************/

extern struct pci_dev *nv_lkpi_pci_devs[NV_MAX_DEVICES];

int nv_drm_probe_devices(void)
{
    nv_drm_update_drm_driver_features();

    /*
     * Conveniently we can get all of the nvidia devices that were initialized
     * by the native nvidia.ko by using our devclass.
     */
    for (int i = 0; i < NV_MAX_DEVICES; i++) {
        nv_gpu_info_t gpu_info;
        struct nvidia_softc *sc = devclass_get_softc(nvidia_devclass, i);
        if (!sc) {
            nv_lkpi_pci_devs[i] = NULL;
            continue;
        }
        nv_state_t *nv = sc->nv_state;

        /*
         * Now we have the state (which gives us the device_t), but what nvidia-drm
         * wants is a pci_dev suitable for use with linuxkpi code. We can use
         * lkpinew_pci_dev to fill in a pci_dev struct,
         */
        struct pci_dev *pdev = lkpinew_pci_dev(sc->dev);
        nv_lkpi_pci_devs[i] = pdev;
        /* TODO: clear the release func, since nvidia.ko is in charge of this? */
        //pdev->release = NULL;

        gpu_info.gpu_id = nv->gpu_id;

        gpu_info.pci_info.domain   = nv->pci_info.domain;
        gpu_info.pci_info.bus      = nv->pci_info.bus;
        gpu_info.pci_info.slot     = nv->pci_info.slot;
        gpu_info.pci_info.function = nv->pci_info.function;
        gpu_info.os_device_ptr = pdev;

        nv_drm_register_drm_device(&gpu_info);
    }

    return 0;
}

LKPI_DRIVER_MODULE(nvidia_drm, nv_drm_init, nv_drm_exit);
MODULE_DEPEND(nvidia_drm, linuxkpi, 1, 1, 1);
MODULE_DEPEND(nvidia_drm, linuxkpi_gplv2, 1, 1, 1);
MODULE_DEPEND(nvidia_drm, drmn, 2, 2, 2);
MODULE_DEPEND(nvidia_drm, dmabuf, 1, 1, 1);
MODULE_DEPEND(nvidia_drm, nvidia, 1, 1, 1);
MODULE_DEPEND(nvidia_drm, nvidia_modeset, 1, 1, 1);
#endif /* NV_DRM_AVAILABLE */
