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

#ifndef __NVIDIA_DRM_H__
#define __NVIDIA_DRM_H__

#include "nvidia-drm-conftest.h"

/*
 * FreeBSD specific variables:
 *
 *  Turn on NV_DRM_AVAILABLE to enable the entire module
 */
#ifndef __linux__

/* linuxkpi specific includes */
#include <linux/device.h>
#include <linux/vmalloc.h>

#include "nv-pci-table.h"

int nv_drm_bsd_probe(struct pci_dev *dev,
			    const struct pci_device_id *ent);

extern struct pci_driver nv_drm_pci_driver;

#include <cpufunc.h> /* sfence support */

/* prototypes for non-static functions */
void *nv_drm_calloc(size_t, size_t);
void nv_drm_free(void *);
char *nv_drm_asprintf(const char *, ...);
void nv_drm_write_combine_flush(void);
int nv_drm_lock_user_pages(unsigned long,
                           unsigned long, struct page ***);
void nv_drm_unlock_user_pages(unsigned long , struct page **);
void *nv_drm_vmap(struct page **, unsigned long);
void nv_drm_vunmap(void *);
uint64_t nv_drm_get_time_usec(void);
void nv_drm_update_drm_driver_features(void);

/* devclass for linux_pci_register_drm_driver */
extern devclass_t nv_drm_devclass;

/* 
 * linuxkpi vmap doesn't use the flags argument as it
 * doesn't seem to be needed. Define VM_USERMAP to 0
 * to make errors go away
 *
 * vmap: sys/compat/linuxkpi/common/src/linux_compat.c
 */
#define VM_USERMAP 0

#endif /* __linux__ */

int nv_drm_init(void);
void nv_drm_exit(void);

#endif /* __NVIDIA_DRM_H__ */
