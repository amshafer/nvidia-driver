/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2020 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-freebsd.h"

void* NV_API_CALL os_pci_init_handle(
    NvU32 domain,
    NvU8  bus,
    NvU8  slot,
    NvU8  function,
    NvU16 *vendor,
    NvU16 *device
)
{
    device_t dev;

    /*
     * Find a PCI device based on its address, and return a unique handle
     * to be used in subsequent calls to read from or write to the config
     * space of this device.
     */

    dev = pci_find_dbsf(domain, bus, slot, function);

    if (dev != NULL) {
        if (vendor)
            *vendor = pci_get_vendor(dev);
        if (device)
            *device = pci_get_device(dev);
    }

    return (void *) dev;
}

NV_STATUS NV_API_CALL os_pci_read_byte(
    void *handle,
    NvU32 offset,
    NvU8 *value
)
{
    if (offset >= 0x100) {
        *value = 0xff;
        return NV_ERR_NOT_SUPPORTED;
    }
    *value = pci_read_config((device_t) handle, offset, 1);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_read_word(
    void *handle,
    NvU32 offset,
    NvU16 *value
)
{
    if (offset >= 0x100) {
        *value = 0xffff;
        return NV_ERR_NOT_SUPPORTED;
    }
    *value = pci_read_config((device_t) handle, offset, 2);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_read_dword(
    void *handle,
    NvU32 offset,
    NvU32 *value
)
{
    if (offset >= 0x100) {
        *value = 0xffffffff;
        return NV_ERR_NOT_SUPPORTED;
    }
    *value = pci_read_config((device_t) handle, offset, 4);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_byte(
    void *handle,
    NvU32 offset,
    NvU8  value
)
{
    if (offset >= 0x100)
        return NV_ERR_NOT_SUPPORTED;

    pci_write_config((device_t) handle, offset, value, 1);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_word(
    void *handle,
    NvU32 offset,
    NvU16 value
)
{
    if (offset >= 0x100)
        return NV_ERR_NOT_SUPPORTED;

    pci_write_config((device_t) handle, offset, value, 2);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_dword(
    void *handle,
    NvU32 offset,
    NvU32 value
)
{
    if (offset >= 0x100)
        return NV_ERR_NOT_SUPPORTED;

    pci_write_config((device_t) handle, offset, value, 4);
    return NV_OK;
}

void NV_API_CALL os_pci_remove(
    void *handle
)
{
    return;
}

NvBool NV_API_CALL os_pci_remove_supported(void)
{
    return NV_FALSE;
}

NV_STATUS NV_API_CALL os_enable_pci_req_atomics(
    void *handle,
    enum os_pci_req_atomics_type type
)
{
    return NV_ERR_NOT_SUPPORTED;
}
