/*******************************************************************************
    Copyright (c) 2016-2020 NVidia Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

/*!
 * @file   nvswitch_freebsd.c
 * @brief  NVSwitch driver kernel interface.
 *         TODO: Implement stubs. 
 */

#include "export_nvswitch.h"
#include <sys/libkern.h>

#define NVSWITCH_OS_ASSERT(_cond)                                               \
    do {                                                                        \
        if (!(_cond)) {                                                         \
            nvswitch_os_assert_log("NVSwitch: Assertion failed in OS layer\n"); \
        }                                                                       \
    } while(0)

NvU64
nvswitch_os_get_platform_time
(
    void
)
{
    return 0ULL;
}

NvU64
nvswitch_os_get_platform_time_epoch
(
    void
)
{
    return nvswitch_os_get_platform_time();
}

void
nvswitch_os_print
(
    const int  log_level,
    const char *fmt,
    ...
)
{
    return;
}

NvlStatus
nvswitch_os_read_registry_dword
(
    void *os_handle,
    const char *name,
    NvU32 *data
)
{
    return -1;
}

NvlStatus
nvswitch_os_read_registery_binary
(
    void *os_handle,
    const char *name,
    NvU8 *data,
    NvU32 length
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

void
nvswitch_os_override_platform
(
    void *os_handle,
    NvBool *rtlsim
)
{
    // Never run on RTL
    *rtlsim = NV_FALSE;
}

NvU32
nvswitch_os_get_device_count
(
    void
)
{
    return 0;
}

NvBool
nvswitch_os_is_uuid_in_blacklist
(
    NvUuid *uuid
)
{
    return NV_FALSE;
}

NvlStatus
nvswitch_os_alloc_contig_memory
(
    void *os_handle,
    void **virt_addr,
    NvU32 size,
    NvBool force_dma32
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

void
nvswitch_os_free_contig_memory
(
    void *os_handle,
    void *virt_addr,
    NvU32 size
)
{
    return;
}

NvlStatus
nvswitch_os_map_dma_region
(
    void *os_handle,
    void *cpu_addr,
    NvU64 *dma_handle,
    NvU32 size,
    NvU32 direction
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}


NvlStatus
nvswitch_os_unmap_dma_region
(
    void *os_handle,
    void *cpu_addr,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

NvlStatus
nvswitch_os_set_dma_mask
(
    void *os_handle,
    NvU32 dma_addr_width
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

NvlStatus
nvswitch_os_sync_dma_region_for_cpu
(
    void *os_handle,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

NvlStatus
nvswitch_os_sync_dma_region_for_device
(
    void *os_handle,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

void *
nvswitch_os_malloc_trace
(
    NvLength size,
    const char *file,
    NvU32 line
)
{
    return NULL;
}

void
nvswitch_os_free
(
    void *pMem
)
{
    return;
}

NvLength
nvswitch_os_strlen
(
    const char *str
)
{
    return strlen(str);
}

char*
nvswitch_os_strncpy
(
    char *dest,
    const char *src,
    NvLength length
)
{
    return strncpy(dest, src, length);
}

int
nvswitch_os_strncmp
(
    const char *s1,
    const char *s2,
    NvLength length
)
{
    return strncmp(s1, s2, length);
}

char*
nvswitch_os_strncat
(
    char *s1,
    const char *s2,
    NvLength length
)
{
    return strncat(s1, s2, length);
}

void *
nvswitch_os_memset
(
    void *pDest,
    int value,
    NvLength size
)
{
    return NULL;
}

void *
nvswitch_os_memcpy
(
    void *pDest,
    const void *pSrc,
    NvLength size
)
{
    return NULL;
}

int
nvswitch_os_memcmp
(
    const void *s1,
    const void *s2,
    NvLength size
)
{
    return memcmp(s1, s2, size);
}

NvU32
nvswitch_os_mem_read32
(
    const volatile void * pAddress
)
{
    return 0;
}

void
nvswitch_os_mem_write32
(
    volatile void *pAddress,
    NvU32 data
)
{
}

NvU64
nvswitch_os_mem_read64
(
    const volatile void *pAddress
)
{
    return 0;
}

void
nvswitch_os_mem_write64
(
    volatile void *pAddress,
    NvU64 data
)
{
}

int
nvswitch_os_snprintf
(
    char *pString,
    NvLength size,
    const char *pFormat,
    ...
)
{
    return 0;
}

int
nvswitch_os_vsnprintf
(
    char *buf,
    NvLength size,
    const char *fmt,
    va_list arglist
)
{
    return vsnprintf(buf, size, fmt, arglist);
}

void
nvswitch_os_assert_log
(
    const char *pFormat,
    ...
)
{
}

/*
 * Sleep for specified milliseconds. Yields the CPU to scheduler.
 */
void
nvswitch_os_sleep
(
    unsigned int ms
)
{
    return;
}

NvlStatus
nvswitch_os_acquire_fabric_mgmt_cap
(
    void *osPrivate,
    NvU64 capDescriptor
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

int
nvswitch_os_is_fabric_manager
(
    void *osPrivate
)
{
    return 0;
}

int
nvswitch_os_is_admin
(
    void
)
{
    return 0;
}

NvlStatus
nvswitch_os_get_os_version
(
    NvU32 *pMajorVer,
    NvU32 *pMinorVer,
    NvU32 *pBuildNum
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

/*!
 * @brief: OS Specific handling to add an event.
 */
NvlStatus
nvswitch_os_add_client_event
(
    void            *osHandle,
    void            *osPrivate,
    NvU32           eventId
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

/*!
 * @brief: OS specific handling to remove all events corresponding to osPrivate.
 */
NvlStatus
nvswitch_os_remove_client_event
(
    void            *osHandle,
    void            *osPrivate
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

/*!
 * @brief: OS specific handling to notify an event.
 */
NvlStatus
nvswitch_os_notify_client_event
(
    void *osHandle,
    void *osPrivate,
    NvU32 eventId
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

/*!
 * @brief: Gets OS specific support for the REGISTER_EVENTS ioctl
 */
NvlStatus
nvswitch_os_get_supported_register_events_params
(
    NvBool *many_events,
    NvBool *os_descriptor
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}

NvlStatus
nvswitch_os_get_pid
(
    NvU32 *pPid
)
{
    return -NVL_ERR_NOT_IMPLEMENTED;
}
