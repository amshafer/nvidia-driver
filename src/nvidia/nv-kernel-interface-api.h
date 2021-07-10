/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2018 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#ifndef _NV_KERNEL_INTERFACE_API_H
#define _NV_KERNEL_INTERFACE_API_H
/**************************************************************************************************************
*
*    File:  nv-kernel-interface-api.h
*
*    Description:
*        Defines the NV API related macros. 
*
**************************************************************************************************************/

#if NVOS_IS_UNIX && NVCPU_IS_X86_64 && defined(__use_altstack__)
#define NV_API_CALL __attribute__((altstack(0)))
#else
#define NV_API_CALL
#endif

#endif /* _NV_KERNEL_INTERFACE_API_H */
