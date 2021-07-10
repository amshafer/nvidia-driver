/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2002 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-freebsd.h"
#include "nv-reg.h"

struct sysctl_ctx_list sysctl_ctx;

struct sysctl_oid *oid_nvidia;
struct sysctl_oid *oid_registry;

static char *option_string = NULL;

void nvidia_sysctl_init(void)
{
    nv_parm_t *entry;

    sysctl_ctx_init(&sysctl_ctx);

    oid_nvidia = SYSCTL_ADD_NODE(&sysctl_ctx,
            SYSCTL_STATIC_CHILDREN(_hw),
            OID_AUTO,
            "nvidia",
            CTLFLAG_RD | CTLFLAG_DYN,
            0,
            "NVIDIA SYSCTL Parent Node");

    SYSCTL_ADD_STRING(&sysctl_ctx,
            SYSCTL_CHILDREN(oid_nvidia),
            OID_AUTO,
            "version",
            CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_DYN,
            (char *)(uintptr_t) pNVRM_ID,
            0,
            "NVIDIA Resource Manager (NVRM) Version");

    oid_registry = SYSCTL_ADD_NODE(&sysctl_ctx,
            SYSCTL_CHILDREN(oid_nvidia),
            OID_AUTO,
            "registry",
            CTLFLAG_RD | CTLFLAG_DYN,
            0,
            "NVIDIA SYSCTL Registry Node");

    entry = nv_parms;
    do {
        SYSCTL_ADD_PROC(&sysctl_ctx,
            SYSCTL_CHILDREN(oid_registry),
            OID_AUTO,
            entry->name,
            CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_DYN,
            entry->data, 0,
            nvidia_sysctl_registry_key,
            "IU", NULL);
        entry++;
    } while(entry->name != NULL);

    option_string = malloc(1, M_NVIDIA, (M_WAITOK | M_ZERO));

    SYSCTL_ADD_PROC(&sysctl_ctx,
            SYSCTL_CHILDREN(oid_registry),
            OID_AUTO, "dwords",
            CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_DYN,
            NULL, 0,
            nvidia_sysctl_registry_dwords,
            "A", NULL);
}

void nvidia_sysctl_exit(void)
{
    sysctl_ctx_free(&sysctl_ctx);
    if (option_string != NULL)
        free((void *)option_string, M_NVIDIA);
}


int nvidia_sysctl_gpu_model(SYSCTL_HANDLER_ARGS)
{
    nv_state_t *nv = arg1;
    device_t dev = nv->handle;
    const char *model_name;
    NvU16 subvendor, subdevice;

    subvendor = pci_get_subvendor(dev);
    subdevice = pci_get_subdevice(dev);

    model_name = rm_get_device_name(nv->pci_info.device_id, subvendor, subdevice);

    return SYSCTL_OUT(req, model_name, strlen(model_name) + 1);
}

int nvidia_sysctl_gpu_uuid(SYSCTL_HANDLER_ARGS)
{
    nv_state_t *nv = arg1;
    nvidia_stack_t *sp;
    char *uuid;
    int ret;

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL)
        return ENOMEM;

    uuid = rm_get_gpu_uuid(sp, nv);

    NV_UMA_ZONE_FREE_STACK(sp);

    if (uuid == NULL)
        return EIO;

    ret = SYSCTL_OUT(req, uuid, strlen(uuid) + 1);
    os_free_mem(uuid);

    return ret;
}

int nvidia_sysctl_gpu_vbios(SYSCTL_HANDLER_ARGS)
{
    nv_state_t *nv = arg1;
    nvidia_stack_t *sp;
    char vbios_version[15];

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL)
        return ENOMEM;

    rm_get_vbios_version(sp, nv, vbios_version);

    NV_UMA_ZONE_FREE_STACK(sp);

    return SYSCTL_OUT(req, vbios_version, strlen(vbios_version) + 1);
}

int nvidia_sysctl_bus_type(SYSCTL_HANDLER_ARGS)
{
    struct nvidia_softc *sc = arg1;
    char *bus_type;

    if (nvidia_pci_find_capability(sc->dev, PCIR_CAP_ID_EXP) != 0)
        bus_type = "PCIe";
    else
        bus_type = "PCI";

    return SYSCTL_OUT(req, bus_type, strlen(bus_type) + 1);
}

int nvidia_sysctl_registry_key(SYSCTL_HANDLER_ARGS)
{
    int error;

    error = sysctl_handle_int(oidp, arg1, 0, req);

    if (error || !req->newptr)
        return error;

    /* refresh the registry with the updated option table */
    os_registry_init();

    return 0;
}

int nvidia_sysctl_registry_dwords(SYSCTL_HANDLER_ARGS)
{
    int error, len;
    char *new_option_string;

    len = strlen(option_string) + 1;
    error = SYSCTL_OUT(req, option_string, len);

    if (error || !req->newptr)
        return error;

    len = (req->newlen - req->newidx);

    new_option_string = malloc((len + 1), M_NVIDIA, M_WAITOK);
    if (!new_option_string)
        return ENOMEM;

    error = SYSCTL_IN(req, new_option_string, len);
    if (error)
        return error;

    free(option_string, M_NVIDIA);

    option_string = new_option_string;
    option_string[len] = '\0';

    nvidia_update_registry(new_option_string);

    return 0;
}

void nv_sysctl_init(nv_state_t *nv)
{
    struct sysctl_oid *oid;
    struct nvidia_softc *sc = nv->os_state;

    char name[4];
    sprintf(name, "%d", device_get_unit(sc->dev));

    sysctl_ctx_init(&sc->sysctl_ctx);

    oid = SYSCTL_ADD_NODE(&sc->sysctl_ctx,
            SYSCTL_CHILDREN(oid_nvidia),
            OID_AUTO,
            "gpus",
            CTLFLAG_RD | CTLFLAG_DYN,
            0,
            "NVIDIA SYSCTL GPUs Node");

    oid = SYSCTL_ADD_NODE(&sc->sysctl_ctx,
            SYSCTL_CHILDREN(oid),
            OID_AUTO,
            name,
            CTLFLAG_RD | CTLFLAG_DYN,
            0,
            "NVIDIA SYSCTL GPU Node");

    SYSCTL_ADD_PROC(&sc->sysctl_ctx,
            SYSCTL_CHILDREN(oid),
            OID_AUTO,
            "model",
            CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_DYN,
            (void *) nv, 0,
            nvidia_sysctl_gpu_model,
            "A",
            "NVIDIA GPU Model Name");

    SYSCTL_ADD_UINT(&sc->sysctl_ctx,
            SYSCTL_CHILDREN(oid),
            OID_AUTO,
            "irq",
            CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_DYN,
            &nv->interrupt_line,
            0,
            "NVIDIA GPU IRQ Number");

    SYSCTL_ADD_PROC(&sc->sysctl_ctx,
            SYSCTL_CHILDREN(oid),
            OID_AUTO,
            "vbios",
            CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_DYN,
            (void *) nv, 0,
            nvidia_sysctl_gpu_vbios,
            "A",
            "NVIDIA GPU VBIOS Version");

    SYSCTL_ADD_PROC(&sc->sysctl_ctx,
            SYSCTL_CHILDREN(oid),
            OID_AUTO,
            "uuid",
            CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_DYN,
            (void *) nv, 0,
            nvidia_sysctl_gpu_uuid,
            "A",
            "NVIDIA GPU UUID");

    SYSCTL_ADD_PROC(&sc->sysctl_ctx,
            SYSCTL_CHILDREN(oid),
            OID_AUTO,
            "type",
            CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_DYN,
            (void *) sc, 0,
            nvidia_sysctl_bus_type,
            "A",
            "NVIDIA GPU Bus Type");
}

void nv_sysctl_exit(nv_state_t *nv)
{
    struct nvidia_softc *sc = nv->os_state;
    sysctl_ctx_free(&sc->sysctl_ctx);
}
