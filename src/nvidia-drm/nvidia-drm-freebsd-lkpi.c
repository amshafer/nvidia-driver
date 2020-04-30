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

/* have to be done first before the LIST_HEAD linux version */
#ifndef __linux__
/* 
 * include the FreeBSD structures (nvidia_softc)
 *  have to grab it from src/nvidia/nv-freebsd.h
 */
#include "nv-misc.h"
#include "../nvidia/os-interface.h"
#define NVRM
#include "../nvidia/nv.h"
#include "../nvidia/nv-freebsd.h"
#endif

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>

#include "nvidia-drm-os-interface.h"
#include "nvidia-drm.h"

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_AVAILABLE)

#include "nv-mm.h"

#ifndef __linux__
#include "nv-gpu-info.h"
#include "nvidia-drm-drv.h"
#include "nvidia-drm-priv.h"
#endif

MODULE_PARM_DESC(
    modeset,
    "Enable atomic kernel modesetting (1 = enable, 0 = disable (default))");
bool nv_drm_modeset_module_param = false;
module_param_named(modeset, nv_drm_modeset_module_param, bool, 0400);

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
  #ifdef __linux__
      #define WRITE_COMBINE_FLUSH()    asm volatile("sfence":::"memory")
  #else
      #define WRITE_COMBINE_FLUSH()    sfence()
  #endif
#elif defined(NVCPU_FAMILY_ARM)
  #if defined(NVCPU_ARM)
    #define WRITE_COMBINE_FLUSH()  { dsb(); outer_sync(); }
  #elif defined(NVCPU_AARCH64)
    #define WRITE_COMBINE_FLUSH()  mb()
  #endif
#elif defined(NVCPU_PPC64LE)
  #ifdef __linux__
      #define WRITE_COMBINE_FLUSH()    asm volatile("sync":::"memory")
  #else
      /* should include powerpc_sync for a cleaner approach */
      #define WRITE_COMBINE_FLUSH()    __asm __volatile("sync":::"memory")
  #endif
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
    const int force = 0;
    int pages_pinned;

    user_pages = nv_drm_calloc(pages_count, sizeof(*user_pages));

    if (user_pages == NULL) {
        return -ENOMEM;
    }

    down_read(&mm->mmap_sem);

    pages_pinned = NV_GET_USER_PAGES(address, pages_count, write, force,
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

#ifdef __linux__
    do_gettimeofday(&tv);
#else
    microtime(&tv);
#endif

    return (((uint64_t)tv.tv_sec) * 1000000) + tv.tv_usec;
}

#endif /* NV_DRM_AVAILABLE */

#ifdef __linux__
/*************************************************************************
164  * Linux loading support code.
165  *************************************************************************/
     
static int __init nv_linux_drm_init(void)
{
    return nv_drm_init();
} 

static void __exit nv_linux_drm_exit(void)
{   
    nv_drm_exit();
}   

module_init(nv_linux_drm_init);
module_exit(nv_linux_drm_exit);

#if defined(MODULE_LICENSE)
  MODULE_LICENSE("MIT");
#endif
#if defined(MODULE_INFO)
  MODULE_INFO(supported, "external");
#endif
#if defined(MODULE_VERSION)
  MODULE_VERSION(NV_VERSION_STRING);
#endif

#else
/*************************************************************************
 * FreeBSD linuxkpi based loading support code.
 *************************************************************************/
/* 
 * we need to probe the pci bus to add our devices so that
 * we can enumerate them later
 */
devclass_t nv_drm_devclass;
struct pci_driver nv_drm_pci_driver = {
	.name = "nvidia-drm-pci",
	.id_table = nv_pci_table,
	.probe = nv_drm_bsd_probe,
	/* .bsdclass = nv_drm_devclass */
	/* removal is done in nv_drm_remove_devices */
};

/*
 * On linux the nvidia driver creates a list of devices,
 * called nv_linux_devices. nvidia-drm usually borrows this
 * list instead of re-probing the devices. Because we do
 * not have such a list, we adapt the nv_drm_probe_devices
 * function into a standalone version that does not rely
 * on a table from the main nvidia driver
 *
 * Essentially, we will create a nv_gpu_info_t struct
 * from the probed device and register it with the drm
 * subsystem.
 */
int nv_global_major_number;
int nv_drm_bsd_probe(struct pci_dev *dev,
			      const struct pci_device_id *ent)
{
	nv_gpu_info_t gpu_info;
	struct nvidia_softc *sc;
	nv_state_t *nv;

	NV_DRM_LOG_INFO("pci_dev %lx ------------------------", (unsigned long)dev);
	NV_DRM_LOG_INFO("->vendor = %d", dev->vendor);
	NV_DRM_LOG_INFO("->device = %d", dev->device);
	NV_DRM_LOG_INFO("->driver = 0x%lx", (unsigned long)dev->pdrv);

	/*
	 * We need to get the GPU id from the FreeBSD devclass
	 * This is absolutely needed as the nvkms kapi
	 * uses the GPU id for its operations
	 */
	for (int i = 0; i < NV_MAX_DEVICES; i++) {
		sc = devclass_get_softc(nvidia_devclass, i);
		if (!sc)
			continue;
		nv = sc->nv_state;

		/* find a matching GPU softc to get an ID from */
		NV_DRM_LOG_INFO("nv->vendor = 0x%lx, ent->vendor = 0x%lx", (unsigned long)nv->pci_info.vendor_id, (unsigned long)ent->vendor);
		NV_DRM_LOG_INFO("nv->vendor = 0x%lx, ent->vendor = 0x%lx", (unsigned long)nv->pci_info.device_id, (unsigned long)ent->device);
		if (nv->pci_info.vendor_id == ent->vendor
		    && nv->pci_info.device_id == ent->device) {
			break;
		}
	}
	if (!nv)
		return 0;

	NV_DRM_LOG_INFO("nv = 0x%lx", (unsigned long)nv);
	NV_DRM_LOG_INFO("nv->gpu_id = 0x%lx", (unsigned long)nv->gpu_id);
	gpu_info.gpu_id = nv->gpu_id;
	gpu_info.os_device_ptr = dev;
	
	nv_drm_register_drm_device(&gpu_info);

	return 1;
}

LKPI_DRIVER_MODULE(nvidia_drm, nv_drm_init, nv_drm_exit);
MODULE_DEPEND(nvidia_drm, linuxkpi, 1, 1, 1);
MODULE_DEPEND(nvidia_drm, drmn, 2, 2, 2);
MODULE_DEPEND(nvidia_drm, nvidia, 1, 1, 1);
MODULE_DEPEND(nvidia_drm, nvidia_modeset, 1, 1, 1);
#endif
