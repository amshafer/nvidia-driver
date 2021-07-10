/*
 * Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.
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

#include "nvidia-drm-conftest.h" /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

#if defined(NV_DRM_DRMP_H_PRESENT)
#include <drm/drmP.h>
#endif
#include <linux/kernel.h>

#include "nvidia-drm-format.h"
#include "nvidia-drm-os-interface.h"

static const u32  nvkms_to_drm_format[] = {
    /* RGB formats */
    [NvKmsSurfaceMemoryFormatA1R5G5B5]    = DRM_FORMAT_ARGB1555,
    [NvKmsSurfaceMemoryFormatX1R5G5B5]    = DRM_FORMAT_XRGB1555,
    [NvKmsSurfaceMemoryFormatR5G6B5]      = DRM_FORMAT_RGB565,
    [NvKmsSurfaceMemoryFormatA8R8G8B8]    = DRM_FORMAT_ARGB8888,
    [NvKmsSurfaceMemoryFormatX8R8G8B8]    = DRM_FORMAT_XRGB8888,
    [NvKmsSurfaceMemoryFormatA2B10G10R10] = DRM_FORMAT_ABGR2101010,
    [NvKmsSurfaceMemoryFormatX2B10G10R10] = DRM_FORMAT_XBGR2101010,

    /* YUV semi-planar formats */
    [NvKmsSurfaceMemoryFormatY8_U8__Y8_V8_N422] = DRM_FORMAT_YUYV,
    [NvKmsSurfaceMemoryFormatU8_Y8__V8_Y8_N422] = DRM_FORMAT_UYVY,
    [NvKmsSurfaceMemoryFormatY8___U8V8_N444]    = DRM_FORMAT_NV24,
    [NvKmsSurfaceMemoryFormatY8___V8U8_N444]    = DRM_FORMAT_NV42,
    [NvKmsSurfaceMemoryFormatY8___U8V8_N422]    = DRM_FORMAT_NV16,
    [NvKmsSurfaceMemoryFormatY8___V8U8_N422]    = DRM_FORMAT_NV61,
    [NvKmsSurfaceMemoryFormatY8___U8V8_N420]    = DRM_FORMAT_NV12,
    [NvKmsSurfaceMemoryFormatY8___V8U8_N420]    = DRM_FORMAT_NV21,

#if defined(DRM_FORMAT_P210)
    [NvKmsSurfaceMemoryFormatY10___U10V10_N422] = DRM_FORMAT_P210,
#endif

#if defined(DRM_FORMAT_P010)
    [NvKmsSurfaceMemoryFormatY10___U10V10_N420] = DRM_FORMAT_P010,
#endif

#if defined(DRM_FORMAT_P012)
    [NvKmsSurfaceMemoryFormatY12___U12V12_N420] = DRM_FORMAT_P012,
#endif
};

bool nv_drm_format_to_nvkms_format(u32 format,
                                   enum NvKmsSurfaceMemoryFormat *nvkms_format)
{
    enum NvKmsSurfaceMemoryFormat i;
    for (i = 0; i < ARRAY_SIZE(nvkms_to_drm_format); i++) {
        /*
         * Note nvkms_to_drm_format[] is sparsely populated: it doesn't
         * handle all NvKmsSurfaceMemoryFormat values, so be sure to skip 0
         * entries when iterating through it.
         */
        if (nvkms_to_drm_format[i] != 0 && nvkms_to_drm_format[i] == format) {
            *nvkms_format = i;
            return true;
        }
    }
    return false;
}

uint32_t *nv_drm_format_array_alloc(
    unsigned int *count,
    const long unsigned int nvkms_format_mask)
{
    enum NvKmsSurfaceMemoryFormat i;
    unsigned int max_count = hweight64(nvkms_format_mask);
    uint32_t *array = nv_drm_calloc(1, sizeof(uint32_t) * max_count);

    if (array == NULL) {
        return NULL;
    }

    *count = 0;
    for_each_set_bit(i, &nvkms_format_mask,
        sizeof(nvkms_format_mask) * BITS_PER_BYTE) {

        if (i > NvKmsSurfaceMemoryFormatMax) {
            break;
        }

        /*
         * Note nvkms_to_drm_format[] is sparsely populated: it doesn't
         * handle all NvKmsSurfaceMemoryFormat values, so be sure to skip 0
         * entries when iterating through it.
         */
        if (nvkms_to_drm_format[i] == 0) {
            continue;
        }
        array[(*count)++] = nvkms_to_drm_format[i];
    }

    if (*count == 0) {
        nv_drm_free(array);
        return NULL;
    }

    return array;
}

#endif
