/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2016 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#define NV_DEFINE_REGISTRY_KEY_TABLE

#include "os-interface.h"
#include "nv.h"
#include "nv-freebsd.h"
#include "nv-reg.h"

void nvidia_update_registry(char *new_option_string)
{
    nv_parm_t *entry;
    nvidia_stack_t *sp;
    char *option_string = NULL;
    char *ptr;
    char *token;
    char *name, *value;
    NvU32 i, data;

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL)
        return;

    if ((option_string = rm_remove_spaces(new_option_string)) == NULL)
    {
        return;
    }

    ptr = option_string;

    while ((token = strsep(&ptr, ";")) != NULL) {
        if (!(name = strsep(&token, "=")) || !strlen(name))
            continue;
        if (!(value = strsep(&token, "=")) || !strlen(value))
            continue;
        if (strsep(&token, "=") != NULL)
            continue;

        data = (NvU32)strtoul(value, NULL, 0);

        for (i = 0; (entry = &nv_parms[i])->name != NULL; i++) {
            if (strcmp(entry->name, name) == 0) {
                *entry->data = data;
                break;
            }
        }

        rm_write_registry_dword(sp, NULL, name, data);
    }

    NV_UMA_ZONE_FREE_STACK(sp);

    // Free the memory allocated by rm_remove_spaces()
    os_free_mem(option_string);
}

#define NV_TUNABLE_MAX_STRLEN 128

static void nvidia_tunable_init(void)
{
    nv_parm_t *entry;
    NvU32 i;
    char *tunable;

    tunable = malloc(NV_TUNABLE_MAX_STRLEN, M_NVIDIA, M_WAITOK);
    if (tunable == NULL)
        return;

    for (i = 0; (entry = &nv_parms[i])->name != NULL; i++) {
       snprintf(tunable, NV_TUNABLE_MAX_STRLEN, "hw.nvidia.registry.%s",
               entry->name);
       TUNABLE_INT_FETCH(tunable, entry->data);
    }

    free(tunable, M_NVIDIA);
}

NV_STATUS NV_API_CALL os_registry_init(void)
{
    nv_parm_t *entry;
    NvU32 i;
    nvidia_stack_t *sp;

    nvidia_tunable_init();

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL)
        return NV_ERR_NO_MEMORY;

    for (i = 0; (entry = &nv_parms[i])->name != NULL; i++)
        rm_write_registry_dword(sp, NULL, entry->name, *entry->data);

    NV_UMA_ZONE_FREE_STACK(sp);

    return NV_OK;
}
