/*
 * Copyright (c) 2017, NVIDIA CORPORATION. All rights reserved.
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

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

#include "nvidia-drm-gem-nvkms-memory.h"
#include "nvidia-drm-helper.h"
#include "nvidia-drm-ioctl.h"

#if defined(NV_DRM_DRM_DRV_H_PRESENT)
#include <drm/drm_drv.h>
#endif

#if defined(NV_DRM_DRM_PRIME_H_PRESENT)
#include <drm/drm_prime.h>
#endif

#include <linux/io.h>

#include <vm/vm_pageout.h>
#include "nv-mm.h"

static void __nv_drm_gem_nvkms_memory_free(struct nv_drm_gem_object *nv_gem)
{
    struct nv_drm_device *nv_dev = nv_gem->nv_dev;
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory =
        to_nv_nvkms_memory(nv_gem);

    if (nv_nvkms_memory->physically_mapped) {
        if (nv_nvkms_memory->pWriteCombinedIORemapAddress != NULL) {
            iounmap(nv_nvkms_memory->pWriteCombinedIORemapAddress);
        }

        nvKms->unmapMemory(nv_dev->pDevice,
                           nv_nvkms_memory->base.pMemory,
                           NVKMS_KAPI_MAPPING_TYPE_USER,
                           nv_nvkms_memory->pPhysicalAddress);
    }

    if (nv_nvkms_memory->pages_count != 0) {
        nvKms->freeMemoryPages((NvU64 *)nv_nvkms_memory->pages);
    }

    /* Free NvKmsKapiMemory handle associated with this gem object */

    nvKms->freeMemory(nv_dev->pDevice, nv_nvkms_memory->base.pMemory);

    nv_drm_free(nv_nvkms_memory);
}

static int __nv_drm_gem_nvkms_mmap(struct nv_drm_gem_object *nv_gem,
                                   struct vm_area_struct *vma)
{
    return drm_gem_mmap_obj(&nv_gem->base,
                drm_vma_node_size(&nv_gem->base.vma_node) << PAGE_SHIFT, vma);
}

static vm_fault_t __nv_drm_gem_nvkms_handle_vma_fault(
    struct nv_drm_gem_object *nv_gem,
    struct vm_area_struct *vma,
    struct vm_fault *vmf)
{
#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory =
        to_nv_nvkms_memory(nv_gem);
    unsigned long address = nv_page_fault_va(vmf);
    struct drm_gem_object *gem = vma->vm_private_data;
    unsigned long page_offset, pfn;
    vm_fault_t ret;

    page_offset = vmf->pgoff - drm_vma_node_start(&gem->vma_node);

    if (nv_nvkms_memory->pages_count == 0) {
        pfn = (unsigned long)(uintptr_t)nv_nvkms_memory->pPhysicalAddress;
        pfn >>= PAGE_SHIFT;
#ifdef __linux__
        /*
         * FreeBSD doesn't set pgoff. We instead have pfn be the base physical
         * address, and we will calculate the index pidx from the virtual address.
         *
         * This only works because linux_cdev_pager_populate passes the pidx as
         * vmf->virtual_address, which is stupid. Then we turn the virtual address
         * into a physical page number, which is also stupid. The stupid cancels
         * out and everything works.
         */
        pfn += page_offset;
#endif
    } else {
        BUG_ON(page_offset >= nv_nvkms_memory->pages_count);
        pfn = page_to_pfn(nv_nvkms_memory->pages[page_offset]);
    }

#ifdef __linux__
#if defined(NV_VMF_INSERT_PFN_PRESENT)
    ret = vmf_insert_pfn(vma, address, pfn);
#else
    ret = vm_insert_pfn(vma, address, pfn);
    switch (ret) {
        case 0:
        case -EBUSY:
            /*
             * EBUSY indicates that another thread already handled
             * the faulted range.
             */
            ret = VM_FAULT_NOPAGE;
            break;
        case -ENOMEM:
            ret = VM_FAULT_OOM;
            break;
        default:
            WARN_ONCE(1, "Unhandled error in %s: %d\n", __FUNCTION__, ret);
            ret = VM_FAULT_SIGBUS;
            break;
    }
#endif /* defined(NV_VMF_INSERT_PFN_PRESENT) */
#else
    /* FreeBSD specific: find location to insert new page */
    vm_pindex_t pidx = OFF_TO_IDX(address);
    vm_object_t obj = vma->vm_obj;
    vm_page_t page;

    VM_OBJECT_WLOCK(obj);
    for (;;) {
        /*
         * First we try to grab our page within the obj, getting it if it exists
         * but don't allocate it if it doesn't.
         */
        page = vm_page_grab(obj, pidx, VM_ALLOC_NOCREAT);
        if (!page) {
            /* Now we create the page */
            page = PHYS_TO_VM_PAGE(IDX_TO_OFF(pfn + pidx));
            if (!page) {
                VM_OBJECT_WUNLOCK(obj);
                return VM_FAULT_SIGBUS;
            }
            /* try to busy it, if not restart this process */
            if (!vm_page_busy_acquire(page, VM_ALLOC_WAITFAIL)) {
                continue;
            }
            /* now we can insert the page in our object */
            if (vm_page_insert(page, obj, pidx)) {
                vm_page_xunbusy(page);
                VM_OBJECT_WUNLOCK(obj);
				vm_wait(NULL);
				VM_OBJECT_WLOCK(obj);
                continue;
            }
            vm_page_valid(page);
        }
        break;
    }
    VM_OBJECT_WUNLOCK(obj);

    ret = VM_FAULT_NOPAGE;

    /*
     * linuxkpi will communicate to vm_fault_populate which pages to
     * map into the address space based on vm_pfn_first and vm_pfn_count
     *  (sys/compat/linuxkpi/common/src/linux_compat.c line 577)
     * we only mapped one page at a time, the page we added was page pidx
     */
    vma->vm_pfn_first = pidx;
    vma->vm_pfn_count = 1;
    return ret;
#endif /* __linux__ */
        return ret;
#endif /* defined(NV_DRM_ATOMIC_MODESET_AVAILABLE) */
    return VM_FAULT_SIGBUS;
}

static struct drm_gem_object *__nv_drm_gem_nvkms_prime_dup(
    struct drm_device *dev,
    const struct nv_drm_gem_object *nv_gem_src);

static int __nv_drm_gem_nvkms_map(
    struct nv_drm_device *nv_dev,
    struct NvKmsKapiMemory *pMemory,
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory,
    uint64_t size)
{
    if (!nv_dev->hasVideoMemory) {
        return 0;
    }

    if (!nvKms->mapMemory(nv_dev->pDevice,
                          pMemory,
                          NVKMS_KAPI_MAPPING_TYPE_USER,
                          &nv_nvkms_memory->pPhysicalAddress)) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to map NvKmsKapiMemory 0x%p",
            pMemory);
        return -ENOMEM;
    }

    nv_nvkms_memory->pWriteCombinedIORemapAddress = ioremap_wc(
            (uintptr_t)nv_nvkms_memory->pPhysicalAddress,
            size);

    if (!nv_nvkms_memory->pWriteCombinedIORemapAddress) {
        NV_DRM_DEV_LOG_INFO(
            nv_dev,
            "Failed to ioremap_wc NvKmsKapiMemory 0x%p",
            pMemory);
    }

    nv_nvkms_memory->physically_mapped = true;

    return 0;
}

static int __nv_drm_gem_map_nvkms_memory_offset(
    struct nv_drm_device *nv_dev,
    struct nv_drm_gem_object *nv_gem,
    uint64_t *offset)
{
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory =
        to_nv_nvkms_memory(nv_gem);

    if (!nv_nvkms_memory->physically_mapped) {
        int ret = __nv_drm_gem_nvkms_map(nv_dev,
                                         nv_nvkms_memory->base.pMemory,
                                         nv_nvkms_memory,
                                         nv_nvkms_memory->base.base.size);
        if (ret) {
           return ret;
        }
    }

    return nv_drm_gem_create_mmap_offset(&nv_nvkms_memory->base, offset);
}

static struct sg_table *__nv_drm_gem_nvkms_memory_prime_get_sg_table(
    struct nv_drm_gem_object *nv_gem)
{
    struct nv_drm_device *nv_dev = nv_gem->nv_dev;
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory =
        to_nv_nvkms_memory(nv_gem);
    struct sg_table *sg_table;

    if (nv_nvkms_memory->pages_count == 0) {
        NV_DRM_DEV_LOG_ERR(
                nv_dev,
                "Cannot create sg_table for NvKmsKapiMemory 0x%p",
                nv_gem->pMemory);
        return NULL;
    }

    sg_table = nv_drm_prime_pages_to_sg(nv_dev->dev,
                                        nv_nvkms_memory->pages,
                                        nv_nvkms_memory->pages_count);

    return sg_table;
}

const struct nv_drm_gem_object_funcs nv_gem_nvkms_memory_ops = {
    .free = __nv_drm_gem_nvkms_memory_free,
    .prime_dup = __nv_drm_gem_nvkms_prime_dup,
    .mmap = __nv_drm_gem_nvkms_mmap,
    .handle_vma_fault = __nv_drm_gem_nvkms_handle_vma_fault,
    .create_mmap_offset = __nv_drm_gem_map_nvkms_memory_offset,
    .prime_get_sg_table = __nv_drm_gem_nvkms_memory_prime_get_sg_table,
};

static int __nv_drm_nvkms_gem_obj_init(
    struct nv_drm_device *nv_dev,
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory,
    struct NvKmsKapiMemory *pMemory,
    uint64_t size)
{
    NvU64 *pages = NULL;
    NvU32 numPages = 0;

    nv_nvkms_memory->pPhysicalAddress = NULL;
    nv_nvkms_memory->pWriteCombinedIORemapAddress = NULL;
    nv_nvkms_memory->physically_mapped = false;

    if (!nvKms->getMemoryPages(nv_dev->pDevice,
                               pMemory,
                               &pages,
                               &numPages) &&
        !nv_dev->hasVideoMemory) {
        /* GetMemoryPages may fail for vidmem allocations,
         * but it should not fail for sysmem allocations. */
        NV_DRM_DEV_LOG_ERR(nv_dev,
            "Failed to get memory pages for NvKmsKapiMemory 0x%p",
            pMemory);
        return -ENOMEM;
    }
    nv_nvkms_memory->pages_count = numPages;
    nv_nvkms_memory->pages = (struct page **)pages;

    nv_drm_gem_object_init(nv_dev,
                           &nv_nvkms_memory->base,
                           &nv_gem_nvkms_memory_ops,
                           size,
                           pMemory);

    return 0;
}

int nv_drm_dumb_create(
    struct drm_file *file_priv,
    struct drm_device *dev, struct drm_mode_create_dumb *args)
{
    struct nv_drm_device *nv_dev = to_nv_device(dev);
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory;
    uint8_t compressible = 0;
    struct NvKmsKapiMemory *pMemory;
    int ret = 0;

    args->pitch = roundup(args->width * ((args->bpp + 7) >> 3),
                          nv_dev->pitchAlignment);

    args->size = args->height * args->pitch;

    /* Core DRM requires gem object size to be aligned with PAGE_SIZE */

    args->size = roundup(args->size, PAGE_SIZE);

    if ((nv_nvkms_memory =
            nv_drm_calloc(1, sizeof(*nv_nvkms_memory))) == NULL) {
        ret = -ENOMEM;
        goto fail;
    }

    if (nv_dev->hasVideoMemory) {
        pMemory = nvKms->allocateVideoMemory(nv_dev->pDevice,
                                             NvKmsSurfaceMemoryLayoutPitch,
                                             NVKMS_KAPI_ALLOCATION_TYPE_SCANOUT,
                                             args->size,
                                             &compressible);
    } else {
        pMemory = nvKms->allocateSystemMemory(nv_dev->pDevice,
                                              NvKmsSurfaceMemoryLayoutPitch,
                                              NVKMS_KAPI_ALLOCATION_TYPE_SCANOUT,
                                              args->size,
                                              &compressible);
    }

    if (pMemory == NULL) {
        ret = -ENOMEM;
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
#ifdef __linux__
	    "Failed to allocate NvKmsKapiMemory for dumb object of size %llu",
#else
	    "Failed to allocate NvKmsKapiMemory for dumb object of size %lu",
#endif
            args->size);
        goto nvkms_alloc_memory_failed;
    }

    ret = __nv_drm_nvkms_gem_obj_init(nv_dev, nv_nvkms_memory, pMemory, args->size);
    if (ret) {
        goto nvkms_gem_obj_init_failed;
    }

    /* Always map dumb buffer memory up front.  Clients are only expected
     * to use dumb buffers for software rendering, so they're not much use
     * without a CPU mapping.
     */
    ret = __nv_drm_gem_nvkms_map(nv_dev, pMemory, nv_nvkms_memory, args->size);
    if (ret) {
        nv_drm_gem_object_unreference_unlocked(&nv_nvkms_memory->base);
        goto fail;
    }

#ifndef __linux__
    /*
     * register the pages with the vm system
     * These pages will be used to back
     * fault requests. Pages are registered
     * as PG_FICTITIOUS to signify device
     * mapped memory
     */
    vm_paddr_t start = (vm_paddr_t)nv_nvkms_memory->pPhysicalAddress;
    vm_paddr_t end = start + args->size;
    NV_DRM_LOG_INFO("nv_drm_dumb_create: at 0x%jx with size 0x%lx.\n", start, end);

    ret = vm_phys_fictitious_reg_range(start, end, VM_MEMATTR_WRITE_COMBINING);
    if (ret) {
	    NV_DRM_LOG_INFO("Failed to register fictitious range 0x%jx-0x%lx (error = %d).\n",
			    start, end, ret);
        nv_drm_gem_object_unreference_unlocked(&nv_nvkms_memory->base);
        goto fail;
    }
#endif

    return nv_drm_gem_handle_create_drop_reference(file_priv,
                                                   &nv_nvkms_memory->base,
                                                   &args->handle);

nvkms_gem_obj_init_failed:
    nvKms->freeMemory(nv_dev->pDevice, pMemory);

nvkms_alloc_memory_failed:
    nv_drm_free(nv_nvkms_memory);

fail:
    return ret;
}

int nv_drm_gem_import_nvkms_memory_ioctl(struct drm_device *dev,
                                         void *data, struct drm_file *filep)
{
    struct nv_drm_device *nv_dev = to_nv_device(dev);
    struct drm_nvidia_gem_import_nvkms_memory_params *p = data;
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory;
    struct NvKmsKapiMemory *pMemory;
    int ret;

    if (!drm_core_check_feature(dev, DRIVER_MODESET)) {
        ret = -EINVAL;
        goto failed;
    }

    if ((nv_nvkms_memory =
            nv_drm_calloc(1, sizeof(*nv_nvkms_memory))) == NULL) {
        ret = -ENOMEM;
        goto failed;
    }

    pMemory = nvKms->importMemory(nv_dev->pDevice,
                                  p->mem_size,
                                  p->nvkms_params_ptr,
                                  p->nvkms_params_size);

    if (pMemory == NULL) {
        ret = -EINVAL;
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to import NVKMS memory to GEM object");
        goto nvkms_import_memory_failed;
    }

    ret = __nv_drm_nvkms_gem_obj_init(nv_dev, nv_nvkms_memory, pMemory, p->mem_size);
    if (ret) {
        goto nvkms_gem_obj_init_failed;
    }

    return nv_drm_gem_handle_create_drop_reference(filep,
                                                   &nv_nvkms_memory->base,
                                                   &p->handle);
nvkms_gem_obj_init_failed:
    nvKms->freeMemory(nv_dev->pDevice, pMemory);

nvkms_import_memory_failed:
    nv_drm_free(nv_nvkms_memory);

failed:
    return ret;
}

int nv_drm_gem_export_nvkms_memory_ioctl(struct drm_device *dev,
                                         void *data, struct drm_file *filep)
{
    struct nv_drm_device *nv_dev = to_nv_device(dev);
    struct drm_nvidia_gem_export_nvkms_memory_params *p = data;
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory = NULL;
    int ret = 0;

    if (!drm_core_check_feature(dev, DRIVER_MODESET)) {
        ret = -EINVAL;
        goto done;
    }

    if (p->__pad != 0) {
        ret = -EINVAL;
        NV_DRM_DEV_LOG_ERR(nv_dev, "Padding fields must be zeroed");
        goto done;
    }

    if ((nv_nvkms_memory = nv_drm_gem_object_nvkms_memory_lookup(
                    dev,
                    filep,
                    p->handle)) == NULL) {
        ret = -EINVAL;
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to lookup NVKMS gem object for export: 0x%08x",
            p->handle);
        goto done;
    }

    if (!nvKms->exportMemory(nv_dev->pDevice,
                             nv_nvkms_memory->base.pMemory,
                             p->nvkms_params_ptr,
                             p->nvkms_params_size)) {
        ret = -EINVAL;
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to export memory from NVKMS GEM object: 0x%08x", p->handle);
        goto done;
    }

done:
    if (nv_nvkms_memory != NULL) {
        nv_drm_gem_object_unreference_unlocked(&nv_nvkms_memory->base);
    }

    return ret;
}

int nv_drm_gem_alloc_nvkms_memory_ioctl(struct drm_device *dev,
                                        void *data, struct drm_file *filep)
{
    struct nv_drm_device *nv_dev = to_nv_device(dev);
    struct drm_nvidia_gem_alloc_nvkms_memory_params *p = data;
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory = NULL;
    struct NvKmsKapiMemory *pMemory;
    enum NvKmsSurfaceMemoryLayout layout;
    enum NvKmsKapiAllocationType type;
    int ret = 0;

    if (!drm_core_check_feature(dev, DRIVER_MODESET)) {
        ret = -EINVAL;
        goto failed;
    }

    if (p->__pad != 0) {
        ret = -EINVAL;
        NV_DRM_DEV_LOG_ERR(nv_dev, "non-zero value in padding field");
        goto failed;
    }

    if ((nv_nvkms_memory =
            nv_drm_calloc(1, sizeof(*nv_nvkms_memory))) == NULL) {
        ret = -ENOMEM;
        goto failed;
    }

    layout = p->block_linear ?
        NvKmsSurfaceMemoryLayoutBlockLinear : NvKmsSurfaceMemoryLayoutPitch;
    type = (p->flags & NV_GEM_ALLOC_NO_SCANOUT) ?
        NVKMS_KAPI_ALLOCATION_TYPE_OFFSCREEN : NVKMS_KAPI_ALLOCATION_TYPE_SCANOUT;

    if (nv_dev->hasVideoMemory) {
        pMemory = nvKms->allocateVideoMemory(nv_dev->pDevice,
                                             layout,
                                             type,
                                             p->memory_size,
                                             &p->compressible);
    } else {
        pMemory = nvKms->allocateSystemMemory(nv_dev->pDevice,
                                              layout,
                                              type,
                                              p->memory_size,
                                              &p->compressible);
    }

    if (pMemory == NULL) {
        ret = -EINVAL;
        NV_DRM_DEV_LOG_ERR(nv_dev,
                           "Failed to allocate NVKMS memory for GEM object");
        goto nvkms_alloc_memory_failed;
    }

    ret = __nv_drm_nvkms_gem_obj_init(nv_dev, nv_nvkms_memory, pMemory,
                                      p->memory_size);
    if (ret) {
        goto nvkms_gem_obj_init_failed;
    }

    return nv_drm_gem_handle_create_drop_reference(filep,
                                                   &nv_nvkms_memory->base,
                                                   &p->handle);

nvkms_gem_obj_init_failed:
    nvKms->freeMemory(nv_dev->pDevice, pMemory);

nvkms_alloc_memory_failed:
    nv_drm_free(nv_nvkms_memory);

failed:
    return ret;
}

static struct drm_gem_object *__nv_drm_gem_nvkms_prime_dup(
    struct drm_device *dev,
    const struct nv_drm_gem_object *nv_gem_src)
{
    struct nv_drm_device *nv_dev = to_nv_device(dev);
    const struct nv_drm_device *nv_dev_src;
    const struct nv_drm_gem_nvkms_memory *nv_nvkms_memory_src;
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory;
    struct NvKmsKapiMemory *pMemory;

    BUG_ON(nv_gem_src == NULL || nv_gem_src->ops != &nv_gem_nvkms_memory_ops);

    nv_dev_src = to_nv_device(nv_gem_src->base.dev);
    nv_nvkms_memory_src = to_nv_nvkms_memory_const(nv_gem_src);

    if ((nv_nvkms_memory =
            nv_drm_calloc(1, sizeof(*nv_nvkms_memory))) == NULL) {
        return NULL;
    }

    pMemory = nvKms->dupMemory(nv_dev->pDevice,
                               nv_dev_src->pDevice, nv_gem_src->pMemory);
    if (pMemory == NULL) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to import NVKMS memory to GEM object");
        goto nvkms_dup_memory_failed;
    }

    if (__nv_drm_nvkms_gem_obj_init(nv_dev,
                                    nv_nvkms_memory,
                                    pMemory,
                                    nv_gem_src->base.size)) {
        goto nvkms_gem_obj_init_failed;
    }

    return &nv_nvkms_memory->base.base;

nvkms_gem_obj_init_failed:
    nvKms->freeMemory(nv_dev->pDevice, pMemory);

nvkms_dup_memory_failed:
    nv_drm_free(nv_nvkms_memory);

    return NULL;
}

int nv_drm_dumb_map_offset(struct drm_file *file,
                           struct drm_device *dev, uint32_t handle,
                           uint64_t *offset)
{
    struct nv_drm_device *nv_dev = to_nv_device(dev);
    struct nv_drm_gem_nvkms_memory *nv_nvkms_memory;
    int ret = -EINVAL;

    if ((nv_nvkms_memory = nv_drm_gem_object_nvkms_memory_lookup(
                    dev,
                    file,
                    handle)) == NULL) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to lookup gem object for mapping: 0x%08x",
            handle);
        return ret;
    }

    ret = __nv_drm_gem_map_nvkms_memory_offset(nv_dev,
                                               &nv_nvkms_memory->base, offset);

    nv_drm_gem_object_unreference_unlocked(&nv_nvkms_memory->base);

    return ret;
}

int nv_drm_dumb_destroy(struct drm_file *file,
                        struct drm_device *dev,
                        uint32_t handle)
{
    return drm_gem_handle_delete(file, handle);
}

#endif
