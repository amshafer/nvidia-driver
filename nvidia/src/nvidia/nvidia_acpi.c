/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2010-2021 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-freebsd.h"

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>
#include <dev/acpica/acpivar.h>

static int nvidia_acpi_lookup_bus(device_t dev, device_t *bus)
{
    do {
        dev = device_get_parent(dev);
        if (dev == NULL)
            break;
    } while (strcmp(device_get_name(dev), "acpi") != 0);

    *bus = dev;
    return ((dev != NULL) ? 0 : ENODEV);
}

static NV_STATUS nvidia_acpi_extract_integer(
    const union acpi_object *acpi_object,
    void  *buffer,
    NvU32  buffer_size,
    NvU32 *data_size
)
{
    if (acpi_object->Type != ACPI_TYPE_INTEGER)
        return NV_ERR_INVALID_ARGUMENT;

    if (acpi_object->Integer.Value & ~0xffffffffULL)
        *data_size = sizeof(acpi_object->Integer.Value);
    else
        *data_size = sizeof(NvU32);

    if ((buffer_size < sizeof(NvU32)) ||
            ((buffer_size < sizeof(acpi_object->Integer.Value)) &&
             (acpi_object->Integer.Value & ~0xffffffffULL)))
    {
        return NV_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(buffer, &acpi_object->Integer.Value, *data_size);

    return NV_OK;
}

static NV_STATUS nvidia_acpi_extract_buffer(
    const union acpi_object *acpi_object,
    void  *buffer,
    NvU32  buffer_size,
    NvU32 *data_size
)
{
    if (acpi_object->Type != ACPI_TYPE_BUFFER)
        return NV_ERR_INVALID_ARGUMENT;

    *data_size = acpi_object->Buffer.Length;

    if (buffer_size < acpi_object->Buffer.Length)
        return NV_ERR_BUFFER_TOO_SMALL;

    memcpy(buffer, acpi_object->Buffer.Pointer, *data_size);

    return NV_OK;
}

static NV_STATUS
nvidia_acpi_extract_object(const union acpi_object *, void *, NvU32, NvU32 *);

static NV_STATUS nvidia_acpi_extract_package(
    const union acpi_object *acpi_object,
    void  *buffer,
    NvU32  buffer_size,
    NvU32 *data_size
)
{
    NV_STATUS status = NV_OK;
    NvU32 i, element_size = 0;

    if (acpi_object->Type != ACPI_TYPE_PACKAGE)
        return NV_ERR_INVALID_ARGUMENT;

    *data_size = 0;
    for (i = 0; i < acpi_object->Package.Count; i++)
    {
        buffer = ((char *)buffer + element_size);
        buffer_size -= element_size;

        status = nvidia_acpi_extract_object(&acpi_object->Package.Elements[i],
                buffer, buffer_size, &element_size);
        if (status != NV_OK)
            break;

        *data_size += element_size;
    }

    return status;
}

static NV_STATUS nvidia_acpi_extract_object(
    const union acpi_object *acpi_object,
    void  *buffer,
    NvU32  buffer_size,
    NvU32 *data_size
)
{
    NV_STATUS status;

    switch (acpi_object->Type)
    {
        case ACPI_TYPE_INTEGER:
            status = nvidia_acpi_extract_integer(acpi_object, buffer,
                    buffer_size, data_size);
            break;

        case ACPI_TYPE_BUFFER:
            status = nvidia_acpi_extract_buffer(acpi_object, buffer,
                    buffer_size, data_size);
            break;

        case ACPI_TYPE_PACKAGE:
            status = nvidia_acpi_extract_package(acpi_object, buffer,
                    buffer_size, data_size);
            break;

        default:
            status = NV_ERR_NOT_SUPPORTED;
    }

    return status;
}

NV_STATUS NV_API_CALL nv_acpi_dsm_method(
    nv_state_t *nv,
    NvU8  *pAcpiDsmGuid,
    NvU32  acpiDsmRev,
    NvBool acpiNvpcfDsmFunction,
    NvU32  acpiDsmSubFunction,
    void  *pInParams,
    NvU16  inParamSize,
    NvU32 *pOutStatus,
    void  *pOutData,
    NvU16 *pSize
)
{
    device_t bus, dev;
    NV_STATUS rmStatus = NV_OK;
    ACPI_STATUS status;
    struct acpi_buffer output = { ACPI_ALLOCATE_BUFFER, NULL };
    union acpi_object *dsm;
    union acpi_object dsm_input[4];
    struct acpi_object_list input = { 4, dsm_input };
    uint32_t data_size;

    dev = device_get_parent(nv->handle);

    if (nvidia_acpi_lookup_bus(dev, &bus) != 0)
        return NV_ERR_NOT_SUPPORTED;

    dsm_input[0].Buffer.Type = ACPI_TYPE_BUFFER;
    dsm_input[0].Buffer.Length = 0x10;
    dsm_input[0].Buffer.Pointer = pAcpiDsmGuid;
    dsm_input[1].Integer.Type = ACPI_TYPE_INTEGER;
    dsm_input[1].Integer.Value = acpiDsmRev;
    dsm_input[2].Integer.Type = ACPI_TYPE_INTEGER;
    dsm_input[2].Integer.Value = acpiDsmSubFunction;
    dsm_input[3].Buffer.Type = ACPI_TYPE_BUFFER;
    dsm_input[3].Buffer.Length = inParamSize;
    dsm_input[3].Buffer.Pointer = pInParams;

    status = ACPI_EVALUATE_OBJECT(bus, dev, "_DSM", &input, &output);
    if (ACPI_FAILURE(status)) {
        nv_printf(NV_DBG_INFO,
            "NVRM: %s: failed to evaluate _DSM method!\n", __FUNCTION__);
        return NV_ERR_GENERIC;
    }

    if (output.Pointer == NULL)
        return NV_ERR_GENERIC;

    dsm = output.Pointer;

    if (pOutStatus != NULL) {
        *pOutStatus = ((dsm->Buffer.Pointer[3] << 24) |
                       (dsm->Buffer.Pointer[2] << 16) |
                       (dsm->Buffer.Pointer[1] << 8) |
                        dsm->Buffer.Pointer[2]);
    }

    rmStatus = nvidia_acpi_extract_object(dsm, pOutData, *pSize, &data_size);
    if (rmStatus != NV_OK) {
        nv_printf(NV_DBG_INFO,
            "NVRM: %s: received invalid _DSM data!\n", __FUNCTION__);
        rmStatus = NV_ERR_GENERIC;
    }

    *pSize = data_size;
    free(output.Pointer, M_TEMP);

    return rmStatus;
}

NV_STATUS NV_API_CALL nv_acpi_dod_method(
    nv_state_t *nv,
    NvU32 *pOutData,
    NvU32 *pSize
)
{
    device_t bus, dev;
    NV_STATUS rmStatus = NV_OK;
    ACPI_STATUS status;
    struct acpi_buffer output = { ACPI_ALLOCATE_BUFFER, NULL };
    union acpi_object *dod;
    uint32_t i, count = (*pSize / sizeof(NvU32));

    dev = device_get_parent(nv->handle);

    if (nvidia_acpi_lookup_bus(dev, &bus) != 0)
        return NV_ERR_NOT_SUPPORTED;

    status = ACPI_EVALUATE_OBJECT(bus, dev, "_DOD", NULL, &output);
    if (ACPI_FAILURE(status)) {
        nv_printf(NV_DBG_INFO,
            "NVRM: %s: failed to evaluate _DOD method!\n", __FUNCTION__);
        return NV_ERR_GENERIC;
    }

    if (output.Pointer == NULL)
        return NV_ERR_GENERIC;

    dod = output.Pointer;
    *pSize = 0;

    if ((dod->Type == ACPI_TYPE_PACKAGE) &&
            (dod->Package.Count <= count)) {
        for (i = 0; i < dod->Package.Count; i++) {
            if (dod->Package.Elements[i].Type != ACPI_TYPE_INTEGER) {
                nv_printf(NV_DBG_INFO,
                    "NVRM: %s: received invalid _DOD entry!\n", __FUNCTION__);
                rmStatus = NV_ERR_GENERIC;
                break;
            } else {
                pOutData[i] = dod->Package.Elements[i].Integer.Value;
                *pSize += sizeof(NvU32);
            }
        }
    } else {
        nv_printf(NV_DBG_INFO,
            "NVRM: %s: found too many _DOD entries!\n", __FUNCTION__);
        rmStatus = NV_ERR_GENERIC;
    }

    free(output.Pointer, M_TEMP);

    return rmStatus;
}

NV_STATUS NV_API_CALL nv_acpi_rom_method(
    nv_state_t *nv,
    NvU32 *pInData,
    NvU32 *pOutData
)
{
    device_t bus, dev;
    NV_STATUS rmStatus = NV_OK;
    ACPI_STATUS status;
    struct acpi_buffer output = { ACPI_ALLOCATE_BUFFER, NULL };
    union acpi_object *rom;
    union acpi_object rom_input[2];
    struct acpi_object_list input = { 2, rom_input };
    uint32_t offset, length;

    dev = device_get_parent(nv->handle);

    if (nvidia_acpi_lookup_bus(dev, &bus) != 0)
        return NV_ERR_NOT_SUPPORTED;

    offset = pInData[0];
    length = pInData[1];

    rom_input[0].Type = ACPI_TYPE_INTEGER;
    rom_input[0].Integer.Value = offset;
    rom_input[1].Type = ACPI_TYPE_INTEGER;
    rom_input[1].Integer.Value = length;

    status = ACPI_EVALUATE_OBJECT(bus, dev, "_ROM", &input, &output);
    if (ACPI_FAILURE(status)) {
        nv_printf(NV_DBG_INFO,
            "NVRM: %s: failed to evaluate _ROM method!\n", __FUNCTION__);
        return NV_ERR_GENERIC;
    }

    if (output.Pointer == NULL)
        return NV_ERR_GENERIC;

    rom = output.Pointer;

    if ((rom->Type == ACPI_TYPE_BUFFER) &&
            (rom->Buffer.Length >= length)) {
        memcpy(pOutData, rom->Buffer.Pointer, length);
    } else {
        nv_printf(NV_DBG_INFO,
            "NVRM: %s: received invalid _ROM data!\n", __FUNCTION__);
        rmStatus = NV_ERR_GENERIC;
    }

    free(output.Pointer, M_TEMP);

    return rmStatus;
}

NV_STATUS NV_API_CALL nv_acpi_ddc_method(
    nv_state_t *nv,
    void  *pEdidBuffer,
    NvU32 *pSize,
    NvBool bReadMultiBlock
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_acpi_get_powersource(NvU32 *ac_plugged)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_acpi_method(
    NvU32  acpi_method,
    NvU32  function,
    NvU32  subFunction,
    void  *inParams,
    NvU16  inParamSize,
    NvU32 *outStatus,
    void  *outData,
    NvU16 *outDataSize
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_acpi_methods_init(NvU32 *handlesPresent)
{
    *handlesPresent = 0;
}

void NV_API_CALL nv_acpi_methods_uninit(void)
{
}

NV_STATUS NV_API_CALL nv_acpi_mux_method(
    nv_state_t *nv,
    NvU32 *pInOut,
    NvU32 muxAcpiId,
    const char *pMethodName
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL nv_acpi_is_battery_present(void)
{
    return NV_FALSE;
}
