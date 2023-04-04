/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2018 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-freebsd.h"

static void nvidia_pci_identify (driver_t *, device_t);
static int  nvidia_pci_probe    (device_t);
static int  nvidia_pci_attach   (device_t);
static int  nvidia_pci_detach   (device_t);

void nvidia_pci_identify(driver_t *driver, device_t parent)
{
    if (device_find_child(parent, "nvidia", -1) == NULL)
        device_add_child(parent, "nvidia", -1);
}

int nvidia_pci_probe(device_t dev)
{
    const char *name;
    const NvU16 device = pci_get_device(dev);
    const NvU16 subvendor = pci_get_subvendor(dev);
    const NvU16 subdevice = pci_get_subdevice(dev);

    if (!rm_is_supported_pci_device(
            pci_get_class(dev),
            pci_get_subclass(dev),
            pci_get_vendor(dev),
            device,
            subvendor,
            subdevice,
            NV_TRUE /* print_legacy_warning */))
    {
        return ENXIO;
    }

    name = rm_get_device_name(device, subvendor, subdevice);

    device_set_desc_copy(dev, name);

    return 0;
}

int nvidia_pci_setup_intr(device_t dev)
{
    int status, flags;
    struct nvidia_softc *sc;

    sc = device_get_softc(dev);

    /* XXX Revisit! (INTR_FAST) */
    flags = (INTR_TYPE_AV | INTR_MPSAFE);

    status = bus_setup_intr(dev, sc->irq, flags, NULL, nvidia_intr, sc,
            &sc->irq_ih);
    if (status) {
        device_printf(dev, "NVRM: HW ISR setup failed.\n");
        goto fail;
    }

fail:
    return status;
}

int nvidia_pci_teardown_intr(device_t dev)
{
    int status;
    struct nvidia_softc *sc;

    sc = device_get_softc(dev);

    status = bus_teardown_intr(dev, sc->irq, sc->irq_ih);
    if (status) {
        device_printf(dev, "NVRM: HW ISR teardown failed.\n");
        goto fail;
    }

fail:
    return status;
}

void nvidia_pci_save_config_space(
    nvidia_stack_t *sp,
    device_t dev
)
{
    struct nvidia_softc *sc = device_get_softc(dev);
    nv_state_t *nv = sc->nv_state;
    NvS16 i;

    for (i = 0; i < NVRM_PCICFG_NUM_DWORDS; i++)
    {
        os_pci_read_dword(dev, (i << 2), &nv->pci_cfg_space[i]);
    }
}

void nvidia_pci_restore_config_space(
    nvidia_stack_t *sp,
    device_t dev
)
{
    struct nvidia_softc *sc = device_get_softc(dev);
    nv_state_t *nv = sc->nv_state;
    NvS16 i;
    NvU32 dword;

    for (i = NVRM_PCICFG_NUM_DWORDS - 1; i >= 0; i--)
    {
        os_pci_read_dword(dev, (i << 2), &dword);
        if (dword != nv->pci_cfg_space[i]) {
            os_pci_write_dword(dev, (i << 2), nv->pci_cfg_space[i]);
        }
    }
}

NvU8 nvidia_pci_find_capability(device_t dev, NvU8 capability)
{
    NvU16 status;
    NvU8 cap_ptr, cap_id;

    status = pci_read_config(dev, PCIR_STATUS, 2);
    status &= PCIM_STATUS_CAPPRESENT;
    if (!status)
        goto failed;

    switch (pci_get_class(dev)) {
        case PCIC_DISPLAY:
        case PCIC_BRIDGE:
            cap_ptr = pci_read_config(dev, PCIR_CAP_PTR, 1);
            break;
        default:
            goto failed;
    }

    do {
        cap_ptr &= 0xfc;
        cap_id = pci_read_config(dev, cap_ptr + PCIR_CAP_LIST_ID, 1);
        if (cap_id == capability) {
            return cap_ptr;
        }
        cap_ptr = pci_read_config(dev, cap_ptr + PCIR_CAP_LIST_NEXT, 1);
    } while (cap_ptr && cap_id != 0xff);

failed:
    return 0;
}

int nvidia_pci_attach(device_t dev)
{
    int status;
    struct nvidia_softc *sc;
    NvU16 word, i, j;
    NvU32 BAR_low, req;
    nvidia_stack_t *sp;

    if (device_get_unit(dev) >= NV_MAX_DEVICES) {
        device_printf(dev, "NVRM: maximum device number exceeded.\n");
        return ENXIO;
    }

    sc = device_get_softc(dev); /* first reference */
    bzero(sc, sizeof(nvidia_softc_t));

    sc->nv_state = malloc(sizeof(nv_state_t), M_NVIDIA, M_WAITOK | M_ZERO);
    if (sc->nv_state == NULL)
        return ENOMEM;

    pci_enable_busmaster(dev);
    word = pci_read_config(dev, PCIR_COMMAND, 2);

    if ((word & PCIM_CMD_BUSMASTEREN) == 0) {
        device_printf(dev, "NVRM: PCI busmaster enable failed.\n");
        return ENXIO;
    }

    pci_enable_io(dev, SYS_RES_MEMORY);
    word = pci_read_config(dev, PCIR_COMMAND, 2);

    if ((word & PCIM_CMD_MEMEN) == 0) {
        device_printf(dev, "NVRM: PCI memory enable failed.\n");
        return ENXIO;
    }

    for (i = 0, j = 0; i < NVRM_PCICFG_NUM_BARS && j < NV_GPU_NUM_BARS; i++) {
        NvU8 offset = NVRM_PCICFG_BAR_OFFSET(i);
        os_pci_read_dword(dev, offset, &BAR_low);
        os_pci_write_dword(dev, offset, 0xffffffff);
        os_pci_read_dword(dev, offset, &req);
        if ((req != 0) /* implemented */ && (req & NVRM_PCICFG_BAR_REQTYPE_MASK)
                == NVRM_PCICFG_BAR_REQTYPE_MEMORY) {
            sc->nv_state->bars[j].offset = offset;
            sc->BAR_rids[j] = offset;
            if ((req & NVRM_PCICFG_BAR_MEMTYPE_MASK) == NVRM_PCICFG_BAR_MEMTYPE_64BIT) {
                i++;
            }
            j++;
        }
        os_pci_write_dword(dev, offset, BAR_low);
    }

    sc->irq_rid = 0;
    sc->iop_rid = 0;

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL) {
        free(sc->nv_state, M_NVIDIA);
        return ENOMEM;
    }

    sc->attach_sp = sp;

    status = nvidia_alloc_hardware(dev);
    if (status) {
        device_printf(dev, "NVRM: NVIDIA hardware alloc failed.\n");
        goto fail;
    }

    status = nvidia_attach(dev);
    if (status) {
        device_printf(dev, "NVRM: NVIDIA driver attach failed.\n");
        goto fail;
    }

    status = nvidia_pci_setup_intr(dev);
    if (status) {
        device_printf(dev, "NVRM: NVIDIA driver interrupt setup failed.\n");
        nvidia_detach(dev);
        goto fail;
    }

    if (!rm_init_private_state(sp, sc->nv_state)) {
        nvidia_pci_teardown_intr(dev);
        device_printf(dev, "NVRM: rm_init_private_state() failed.\n");
        nvidia_detach(dev);
        status = ENOMEM;
        goto fail;
    }

    if (!nvidia_lock_init_locks(sp, sc->nv_state)) {
        rm_free_private_state(sp, sc->nv_state);
        nvidia_pci_teardown_intr(dev);
        nvidia_detach(dev);
        status = ENOMEM;
        goto fail;
    }

    callout_init(&sc->timer, CALLOUT_MPSAFE);
    sx_init(&sc->api_sx, "dev.api_sx");

    return 0;

fail:
    nvidia_free_hardware(dev);

    sc->attach_sp = NULL;
    NV_UMA_ZONE_FREE_STACK(sp);

    free(sc->nv_state, M_NVIDIA);

    return status;
}

int nvidia_pci_detach(device_t dev)
{
    int status;
    nvidia_stack_t *sp;
    struct nvidia_softc *sc;
    nv_state_t *nv;

    /*
     * Check if the device is still in use before accepting the
     * detach request; this event can happen even when the module
     * usage count is non-zero!
     */
    sc = device_get_softc(dev);
    nv = sc->nv_state;

    nv_lock_api(nv);

    if (sc->refcnt != 0) { /* XXX Fix me? (refcnt) */
        nv_unlock_api(nv);
        return EBUSY;
    }

    nv_unlock_api(nv);
    sx_destroy(&sc->api_sx);

    status = nvidia_pci_teardown_intr(dev);
    if (status)
        goto fail;

    status = nvidia_detach(dev);
    if (status) {
        device_printf(dev, "NVRM: NVIDIA driver detach failed.\n");
        goto fail;
    }

    sp = sc->attach_sp;

    nvidia_lock_destroy_locks(sp, sc->nv_state);

    rm_free_private_state(sp, sc->nv_state);
    nvidia_free_hardware(dev);

    sc->attach_sp = NULL;
    NV_UMA_ZONE_FREE_STACK(sp);

    free(sc->nv_state, M_NVIDIA);

fail:
    /* XXX Fix me? (state) */
    return status;
}

static device_method_t nvidia_pci_methods[] = {
    DEVMETHOD( device_identify, nvidia_pci_identify ),
    DEVMETHOD( device_probe,    nvidia_pci_probe    ),
    DEVMETHOD( device_attach,   nvidia_pci_attach   ),
    DEVMETHOD( device_detach,   nvidia_pci_detach   ),
#ifdef NV_SUPPORT_ACPI_PM
    DEVMETHOD( device_suspend,  nvidia_suspend      ),
    DEVMETHOD( device_resume,   nvidia_resume       ),
#endif
    { 0, 0 }
};

static driver_t nvidia_pci_driver = {
    "nvidia",
    nvidia_pci_methods,
    sizeof(struct nvidia_softc)
};

#if __FreeBSD_version >= 1400058
DRIVER_MODULE(nvidia, vgapci, nvidia_pci_driver, nvidia_modevent, 0);
#else
DRIVER_MODULE(nvidia, vgapci, nvidia_pci_driver, nvidia_devclass, nvidia_modevent, 0);
#endif
MODULE_VERSION(nvidia, 1);

MODULE_DEPEND(nvidia, mem, 1, 1, 1);
MODULE_DEPEND(nvidia, io, 1, 1, 1);

#ifdef NV_SUPPORT_LINUX_COMPAT /* (COMPAT_LINUX || COMPAT_LINUX32) */
MODULE_DEPEND(nvidia, linux, 1, 1, 1);
#if defined(NVCPU_X86_64)
MODULE_DEPEND(nvidia, linux_common, 1, 1, 1);
#endif
#endif
