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

#if defined(NV_DRM_AVAILABLE)

#if defined(NV_DRM_DRM_PRIME_H_PRESENT)
#include <drm/drm_prime.h>
#endif

#include "nvidia-drm-gem-user-memory.h"
#include "nvidia-drm-helper.h"
#include "nvidia-drm-ioctl.h"

#include "linux/dma-buf.h"
#include "linux/mm.h"
#include "nv-mm.h"
#include <vm/vm_pageout.h>

static inline
void __nv_drm_gem_user_memory_free(struct nv_drm_gem_object *nv_gem)
{
    struct nv_drm_gem_user_memory *nv_user_memory = to_nv_user_memory(nv_gem);

    nv_drm_unlock_user_pages(nv_user_memory->pages_count,
                             nv_user_memory->pages);

    nv_drm_free(nv_user_memory);
}

static struct sg_table *__nv_drm_gem_user_memory_prime_get_sg_table(
    struct nv_drm_gem_object *nv_gem)
{
    struct nv_drm_gem_user_memory *nv_user_memory = to_nv_user_memory(nv_gem);
    struct drm_gem_object *gem = &nv_gem->base;

    return nv_drm_prime_pages_to_sg(gem->dev,
                                    nv_user_memory->pages,
                                    nv_user_memory->pages_count);
}

static void *__nv_drm_gem_user_memory_prime_vmap(
    struct nv_drm_gem_object *nv_gem)
{
    struct nv_drm_gem_user_memory *nv_user_memory = to_nv_user_memory(nv_gem);

    return nv_drm_vmap(nv_user_memory->pages,
                           nv_user_memory->pages_count);
}

static void __nv_drm_gem_user_memory_prime_vunmap(
    struct nv_drm_gem_object *gem,
    void *address)
{
    nv_drm_vunmap(address);
}

static int __nv_drm_gem_user_memory_mmap(struct nv_drm_gem_object *nv_gem,
                                         struct vm_area_struct *vma)
{
    int ret = drm_gem_mmap_obj(&nv_gem->base,
                drm_vma_node_size(&nv_gem->base.vma_node) << PAGE_SHIFT, vma);

    if (ret < 0) {
        return ret;
    }

    /*
     * Enforce that user-memory GEM mappings are MAP_SHARED, to prevent COW
     * with MAP_PRIVATE and VM_MIXEDMAP
     */
    if (!(vma->vm_flags & VM_SHARED)) {
        return -EINVAL;
    }

    vma->vm_flags &= ~VM_PFNMAP;
    vma->vm_flags &= ~VM_IO;
    vma->vm_flags |= VM_MIXEDMAP;

    return 0;
}

static vm_fault_t __nv_drm_gem_user_memory_handle_vma_fault(
    struct nv_drm_gem_object *nv_gem,
    struct vm_area_struct *vma,
    struct vm_fault *vmf)
{
    struct nv_drm_gem_user_memory *nv_user_memory = to_nv_user_memory(nv_gem);
    unsigned long address = nv_page_fault_va(vmf);
    struct drm_gem_object *gem = vma->vm_private_data;
    unsigned long page_offset;
    vm_fault_t ret;

    page_offset = vmf->pgoff - drm_vma_node_start(&gem->vma_node);

    BUG_ON(page_offset > nv_user_memory->pages_count);

#ifndef __linux__
    /*
     * FreeBSD specific: find location to insert new page
     *
     * FreeBSD doesn't set pgoff. We instead have pfn be the base physical
     * address, and we will calculate the index pidx from the virtual address.
     *
     * This only works because linux_cdev_pager_populate passes the pidx as
     * vmf->virtual_address, which is stupid. Then we turn the virtual address
     * into a physical page number, which is also stupid. The stupid cancels
     * out and everything works.
     */
    unsigned long pfn = page_to_pfn(nv_user_memory->pages[page_offset]);
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
#else /* !defined(__linux__) */
    ret = vm_insert_page(vma, address, nv_user_memory->pages[page_offset]);
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
#endif /* !defined(__linux__) */

    return ret;
}

static int __nv_drm_gem_user_create_mmap_offset(
    struct nv_drm_device *nv_dev,
    struct nv_drm_gem_object *nv_gem,
    uint64_t *offset)
{
    (void)nv_dev;
    return nv_drm_gem_create_mmap_offset(nv_gem, offset);
}

const struct nv_drm_gem_object_funcs __nv_gem_user_memory_ops = {
    .free = __nv_drm_gem_user_memory_free,
    .prime_get_sg_table = __nv_drm_gem_user_memory_prime_get_sg_table,
    .prime_vmap = __nv_drm_gem_user_memory_prime_vmap,
    .prime_vunmap = __nv_drm_gem_user_memory_prime_vunmap,
    .mmap = __nv_drm_gem_user_memory_mmap,
    .handle_vma_fault = __nv_drm_gem_user_memory_handle_vma_fault,
    .create_mmap_offset = __nv_drm_gem_user_create_mmap_offset,
};

int nv_drm_gem_import_userspace_memory_ioctl(struct drm_device *dev,
                                             void *data, struct drm_file *filep)
{
    struct nv_drm_device *nv_dev = to_nv_device(dev);

    struct drm_nvidia_gem_import_userspace_memory_params *params = data;
    struct nv_drm_gem_user_memory *nv_user_memory;

    struct page **pages = NULL;
    unsigned long pages_count = 0;

    int ret = 0;

    if ((params->size % PAGE_SIZE) != 0) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
#ifdef __linux__
            "Userspace memory 0x%llx size should be in a multiple of page "
#else
	    "Userspace memory 0x%lx size should be in a multiple of page "
#endif
            "size to create a gem object",
            params->address);
        return -EINVAL;
    }

    pages_count = params->size / PAGE_SIZE;

    ret = nv_drm_lock_user_pages(params->address, pages_count, &pages);

    if (ret != 0) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
#ifdef __linux__
            "Failed to lock user pages for address 0x%llx: %d",
#else
	    "Failed to lock user pages for address 0x%lx: %d",
#endif
            params->address, ret);
        return ret;
    }

    if ((nv_user_memory =
            nv_drm_calloc(1, sizeof(*nv_user_memory))) == NULL) {
        ret = -ENOMEM;
        goto failed;
    }

    nv_user_memory->pages = pages;
    nv_user_memory->pages_count = pages_count;

    nv_drm_gem_object_init(nv_dev,
                           &nv_user_memory->base,
                           &__nv_gem_user_memory_ops,
                           params->size,
                           NULL /* pMemory */);

    return nv_drm_gem_handle_create_drop_reference(filep,
                                                   &nv_user_memory->base,
                                                   &params->handle);

failed:
    nv_drm_unlock_user_pages(pages_count, pages);

    return ret;
}

#endif
