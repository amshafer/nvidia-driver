/*******************************************************************************
    Copyright (c) 2015-2019 NVidia Corporation

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
 * @file   nvlink_freebsd.c
 * @brief  Nvlink Core driver and common utility functions that 
 *         interface with kernel.
 *         TODO: Implement stubs. 
 */

#include "nvlink_os.h"

#include <sys/cdefs.h>
#include <sys/libkern.h>

void
nvlink_print
(
    const char *file,
    int         line,
    const char *function,
    int         log_level,
    const char *fmt,
    ...
)
{
    return;
}

void * nvlink_malloc(NvLength size)
{
    return NULL;
}

void nvlink_free(void *ptr)
{
    return;
}

char * nvlink_strcpy(char *dest, const char *src)
{
    return NULL;
}

int nvlink_strcmp(const char *dest, const char *src)
{
    return 0;
}

NvLength nvlink_strlen(const char *s)
{
    return 0;
}

int nvlink_snprintf(char *dest, NvLength size, const char *fmt, ...)
{
    return 0;
}

NvU32 nvlink_memRd32(const volatile void * address)
{
    return 0;
}

void nvlink_memWr32(volatile void *address, NvU32 data)
{
}

NvU64 nvlink_memRd64(const volatile void * address)
{
    return 0;
}

void nvlink_memWr64(volatile void *address, NvU64 data)
{
}

void * nvlink_memset(void *dest, int value, NvLength size)
{
    return NULL;
}

void * nvlink_memcpy(void *dest, const void *src, NvLength size)
{
    return NULL;
}

int nvlink_memcmp(const void *s1, const void *s2, NvLength size)
{
    return memcmp(s1, s2, size);
}

void nvlink_sleep(unsigned int ms)
{
    return;
}

void nvlink_assert(int cond)
{
}

void * nvlink_allocLock(void)
{
    return NULL;
}

void nvlink_acquireLock(void *hLock)
{
}

void nvlink_releaseLock(void *hLock)
{
}

void nvlink_freeLock(void *hLock)
{
}

NvBool nvlink_isLockOwner(void *hLock)
{
    return NV_FALSE;
}

NvlStatus nvlink_acquire_fabric_mgmt_cap(void *osPrivate, NvU64 capDescriptor)
{
    return NVL_ERR_NOT_IMPLEMENTED;
}

int nvlink_is_fabric_manager(void *osPrivate)
{
    return 0;
}

int nvlink_is_admin(void)
{
    return 0;
}
