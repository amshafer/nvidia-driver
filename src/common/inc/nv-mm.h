/*******************************************************************************
    Copyright (c) 2016-2017 NVIDIA Corporation

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
#ifndef __NV_MM_H__
#define __NV_MM_H__

#include "conftest.h"

#if !defined(NV_VM_FAULT_T_IS_PRESENT)
typedef int vm_fault_t;
#endif

/* get_user_pages
 *
 * The 8-argument version of get_user_pages was deprecated by commit 
 * (2016 Feb 12: cde70140fed8429acf7a14e2e2cbd3e329036653)for the non-remote case 
 * (calling get_user_pages with current and current->mm).
 *
 * Completely moved to the 6 argument version of get_user_pages -
 * 2016 Apr 4: c12d2da56d0e07d230968ee2305aaa86b93a6832
 *
 * write and force parameters were replaced with gup_flags by - 
 * 2016 Oct 12: 768ae309a96103ed02eb1e111e838c87854d8b51
 *
 * A 7-argument version of get_user_pages was introduced into linux-4.4.y by
 * commit 8e50b8b07f462ab4b91bc1491b1c91bd75e4ad40 which cherry-picked the
 * replacement of the write and force parameters with gup_flags
 *
 */

#if defined(NV_GET_USER_PAGES_HAS_TASK_STRUCT)
    #if defined(NV_GET_USER_PAGES_HAS_WRITE_AND_FORCE_ARGS)
        #define NV_GET_USER_PAGES(start, nr_pages, write, force, pages, vmas) \
            get_user_pages(current, current->mm, start, nr_pages, write, force, pages, vmas)
    #else
        #include <linux/mm.h>
        #include <linux/sched.h>

        static inline long NV_GET_USER_PAGES(unsigned long start,
                                             unsigned long nr_pages,
                                             int write,
                                             int force,
                                             struct page **pages,
                                             struct vm_area_struct **vmas)
        {
            unsigned int flags = 0;

            if (write)
                flags |= FOLL_WRITE;
            if (force)
                flags |= FOLL_FORCE;

            return get_user_pages(current, current->mm, start, nr_pages, flags,
                                  pages, vmas);
        }
    #endif
#else
    #if defined(NV_GET_USER_PAGES_HAS_WRITE_AND_FORCE_ARGS)
        #define NV_GET_USER_PAGES get_user_pages
    #else
        #include <linux/mm.h>

        static inline long NV_GET_USER_PAGES(unsigned long start,
                                             unsigned long nr_pages,
                                             int write,
                                             int force,
                                             struct page **pages,
                                             struct vm_area_struct **vmas)
        {
            unsigned int flags = 0;

            if (write)
                flags |= FOLL_WRITE;
            if (force)
                flags |= FOLL_FORCE;

            return get_user_pages(start, nr_pages, flags, pages, vmas);
        }
    #endif
#endif

/* get_user_pages_remote() was added by:
 *   2016 Feb 12: 1e9877902dc7e11d2be038371c6fbf2dfcd469d7
 *
 * The very next commit (cde70140fed8429acf7a14e2e2cbd3e329036653)
 * deprecated the 8-argument version of get_user_pages for the
 * non-remote case (calling get_user_pages with current and current->mm).
 *
 * The guidelines are: call NV_GET_USER_PAGES_REMOTE if you need the 8-argument
 * version that uses something other than current and current->mm. Use
 * NV_GET_USER_PAGES if you are refering to current and current->mm.
 *
 * Note that get_user_pages_remote() requires the caller to hold a reference on
 * the task_struct (if non-NULL) and the mm_struct. This will always be true
 * when using current and current->mm. If the kernel passes the driver a vma
 * via driver callback, the kernel holds a reference on vma->vm_mm over that
 * callback.
 *
 * get_user_pages_remote() added 'locked' parameter
 *   2016 Dec 14:5b56d49fc31dbb0487e14ead790fc81ca9fb2c99
 */

#if defined(NV_GET_USER_PAGES_REMOTE_PRESENT)
    #if defined(NV_GET_USER_PAGES_REMOTE_HAS_WRITE_AND_FORCE_ARGS)
        #define NV_GET_USER_PAGES_REMOTE    get_user_pages_remote
    #else
        static inline long NV_GET_USER_PAGES_REMOTE(struct task_struct *tsk,
                                                    struct mm_struct *mm,
                                                    unsigned long start,
                                                    unsigned long nr_pages,
                                                    int write,
                                                    int force,
                                                    struct page **pages,
                                                    struct vm_area_struct **vmas)
        {
            unsigned int flags = 0;

            if (write)
                flags |= FOLL_WRITE;
            if (force)
                flags |= FOLL_FORCE;

        #if defined(NV_GET_USER_PAGES_REMOTE_HAS_LOCKED_ARG)

               return get_user_pages_remote(tsk, mm, start, nr_pages, flags,
                                            pages, vmas, NULL);

        #else

               return get_user_pages_remote(tsk, mm, start, nr_pages, flags,
                                            pages, vmas);

        #endif

        }
    #endif
#else
    #if defined(NV_GET_USER_PAGES_HAS_WRITE_AND_FORCE_ARGS)
        #define NV_GET_USER_PAGES_REMOTE    get_user_pages
    #else
        #include <linux/mm.h>
        #include <linux/sched.h>

        static inline long NV_GET_USER_PAGES_REMOTE(struct task_struct *tsk,
                                                    struct mm_struct *mm,
                                                    unsigned long start,
                                                    unsigned long nr_pages,
                                                    int write,
                                                    int force,
                                                    struct page **pages,
                                                    struct vm_area_struct **vmas)
        {
            unsigned int flags = 0;

            if (write)
                flags |= FOLL_WRITE;
            if (force)
                flags |= FOLL_FORCE;

            return get_user_pages(tsk, mm, start, nr_pages, flags, pages, vmas);
        }
    #endif
#endif


/*
 * The .virtual_address field was effectively renamed to .address, by these
 * two commits:
 *
 *  struct vm_fault: .address was added by:
 *   2016-12-14  82b0f8c39a3869b6fd2a10e180a862248736ec6f
 *
 *  struct vm_fault: .virtual_address was removed by:
 *   2016-12-14  1a29d85eb0f19b7d8271923d8917d7b4f5540b3e
 */
static inline unsigned long nv_page_fault_va(struct vm_fault *vmf)
{
#if defined(NV_VM_FAULT_HAS_ADDRESS)
    return vmf->address;
#else
    return (unsigned long)(vmf->virtual_address);
#endif
}

#endif // __NV_MM_H__
