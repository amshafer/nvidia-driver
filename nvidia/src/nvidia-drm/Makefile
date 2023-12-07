# Build NVIDIA DRM components using the linuxkpi
# inspired by the linuxkpi makefile
#
# Austin Shafer - 2019

SRCS += \
	bus_if.h \
        device_if.h \
        pci_if.h \
        vnode_if.h \
        usb_if.h \
        opt_usb.h \
	opt_compat.h \
	opt_drm.h \
	opt_syscons.h \
        opt_stack.h

SRCS += \
	nvidia-drm-conftest.h \
	nvidia-drm-connector.h \
	nvidia-drm-crtc.h \
	nvidia-drm-drv.h \
	nvidia-drm-encoder.h \
	nvidia-drm-fb.h \
	nvidia-drm-format.h \
	nvidia-drm-gem-dma-buf.h \
	nvidia-drm-gem-nvkms-memory.h \
	nvidia-drm-gem-user-memory.h \
	nvidia-drm-gem.h \
	nvidia-drm-helper.h \
	nvidia-drm-ioctl.h \
	nvidia-drm-modeset.h \
	nvidia-drm-os-interface.h \
	nvidia-drm-fence.h \
	nvidia-drm-priv.h \
	nvidia-drm-utils.h \
	nv-pci-table.h \
	nvidia-drm.h

SRCS += \
	nvidia-drm-connector.c \
	nvidia-drm-crtc.c \
	nvidia-drm-drv.c \
	nvidia-drm-encoder.c \
	nvidia-drm-fb.c \
	nvidia-drm-format.c \
	nvidia-drm-freebsd-lkpi.c \
	nvidia-drm-gem-dma-buf.c \
	nvidia-drm-gem-nvkms-memory.c \
	nvidia-drm-gem-user-memory.c \
	nvidia-drm-gem.c \
	nvidia-drm-helper.c \
	nvidia-drm-modeset.c \
	nvidia-drm-fence.c \
	nvidia-drm-utils.c \
	nv-pci-table.c \
	nvidia-drm.c


KMOD = nvidia-drm

.ifndef BSDVER
BSDVER != /sbin/sysctl -n kern.osreldate
.endif

KMODDIR ?= /boot/modules

# So that the build can include machine/stdarg.h
CFLAGS += -Imachine

# So that the build can include sys/stddef.h
CFLAGS += -I${SYSDIR}/sys

CFLAGS += -g -I/usr/include -I../common/inc -O0 -Wno-visibility -Wno-error=unused-but-set-variable -Wno-error=missing-prototypes

# to workaround dma-buf-map.h
CFLAGS += -Wno-error=pointer-arith

# make sure /usr/include is before all the other includes
#CFLAGS = "-I/usr/include/ $CFLAGS"

CFLAGS += -DNV_VERSION_STRING=\"535.129.03\"

include ../common/optional-cflags.mk

# we need to get the linux kpi headers for compilation. BSDSRCTOP
# is the top of a FreeBSD src tree (or empty to use /sys)
BSDSRCTOP ?= /usr/src
# FreeBSD linuxkpi specific headers
# This is the path at which https://github.com/freebsd/drm-kmod is installed
DRMKMODDIR ?= ${HOME}/git/drm-kmod

NV_CONFTEST_CFLAGS = \
        -I${DRMKMODDIR}/linuxkpi/bsd/include \
        -I${DRMKMODDIR}/linuxkpi/gplv2/include/ \
        -I${BSDSRCTOP}/sys/compat/linuxkpi/common/include/ \
        -I${DRMKMODDIR}/linuxkpi/dummy/include/ \
        -I${BSDSRCTOP}/sys/compat/linuxkpi/dummy/include/ \
        -I${DRMKMODDIR}/include/ \
        -I${DRMKMODDIR}/include/uapi/ \
        -I${DRMKMODDIR}/drivers/gpu/ \
        -I${BSDSRCTOP}/sys/contrib/ck/include

CFLAGS += ${NV_CONFTEST_CFLAGS}

# add src/nvidia as we need headers from there for nvidia_softc
# we use the softc to get the device_t during probing
CFLAGS += -I../nvidia/

CFLAGS += -Wno-cast-qual -Wno-incompatible-pointer-types-discards-qualifiers

#
# Register the conftests needed by nvidia-drm.ko
#

# First we generate conftest/headers.h, which tells the rest what headers
# are available

# to include conftest/headers.h
NV_CONFTEST_CFLAGS+=-I. -D_KERNEL -DKLD_MODULE -nostdinc -I/usr/src/sys -I/usr/src/sys/contrib/ck/include 

# Mark the linux version we support.
# This solves issues with things like ww_mutex_trylock, we will have
# to bump this manually over time unfortunately
.include "${DRMKMODDIR}/linuxkpi_version.mk"
NV_CONFTEST_CFLAGS += -DLINUXKPI_VERSION=${LINUXKPI_VERSION_NUMBER}

conftest/headers.h: ${PWD}/conftest.sh ${DRMKMODDIR}
	mkdir -p conftest
	${PWD}/conftest.sh '${CC}' x86_64 ${DRMKMODDIR} this_arg_not_used_on_bsd test_kernel_headers '${NV_CONFTEST_CFLAGS}' > conftest/headers.h

NV_CONFTEST_GENERIC_COMPILE_TESTS += drm_available
NV_CONFTEST_GENERIC_COMPILE_TESTS += drm_atomic_available
NV_CONFTEST_GENERIC_COMPILE_TESTS += is_export_symbol_gpl_refcount_inc
NV_CONFTEST_GENERIC_COMPILE_TESTS += is_export_symbol_gpl_refcount_dec_and_test
NV_CONFTEST_GENERIC_COMPILE_TESTS += drm_alpha_blending_available
NV_CONFTEST_GENERIC_COMPILE_TESTS += drm_gem_prime_fd_to_handle
NV_CONFTEST_GENERIC_COMPILE_TESTS += drm_gem_prime_handle_to_fd

conftest/generic.h: ${PWD}/conftest.sh ${DRMKMODDIR}
	mkdir -p conftest
	${PWD}/conftest.sh '${CC}' x86_64 ${DRMKMODDIR} this_arg_not_used_on_bsd compile_tests '${NV_CONFTEST_CFLAGS}' ${NV_CONFTEST_GENERIC_COMPILE_TESTS} > conftest/generic.h

NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_dev_unref
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_reinit_primary_mode_group
NV_CONFTEST_FUNCTION_COMPILE_TESTS += get_user_pages_remote
NV_CONFTEST_FUNCTION_COMPILE_TESTS += get_user_pages
NV_CONFTEST_FUNCTION_COMPILE_TESTS += pin_user_pages_remote
NV_CONFTEST_FUNCTION_COMPILE_TESTS += pin_user_pages
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_gem_object_lookup
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_atomic_state_ref_counting
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_driver_has_gem_prime_res_obj
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_atomic_helper_connector_dpms
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_connector_funcs_have_mode_in_name
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_connector_has_vrr_capable_property
NV_CONFTEST_FUNCTION_COMPILE_TESTS += vmf_insert_pfn
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_framebuffer_get
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_gem_object_get
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_dev_put
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_format_num_planes
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_connector_for_each_possible_encoder
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_rotation_available
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_vma_offset_exact_lookup_locked
NV_CONFTEST_FUNCTION_COMPILE_TESTS += drm_gem_object_put_unlocked
NV_CONFTEST_FUNCTION_COMPILE_TESTS += nvhost_dma_fence_unpack
NV_CONFTEST_FUNCTION_COMPILE_TESTS += list_is_first
NV_CONFTEST_FUNCTION_COMPILE_TESTS += timer_setup

conftest/function.h: ${PWD}/conftest.sh ${DRMKMODDIR}
	mkdir -p conftest
	${PWD}/conftest.sh '${CC}' x86_64 ${DRMKMODDIR} this_arg_not_used_on_bsd compile_tests '${NV_CONFTEST_CFLAGS}' ${NV_CONFTEST_FUNCTION_COMPILE_TESTS} > conftest/function.h

NV_CONFTEST_TYPE_COMPILE_TESTS += drm_bus_present
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_bus_has_bus_type
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_bus_has_get_irq
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_bus_has_get_name
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_has_device_list
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_has_legacy_dev_list
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_has_set_busid
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_crtc_state_has_connectors_changed
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_init_function_args
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_helper_mode_fill_fb_struct
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_master_drop_has_from_release_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_unload_has_int_return_type
NV_CONFTEST_TYPE_COMPILE_TESTS += vm_fault_has_address
NV_CONFTEST_TYPE_COMPILE_TESTS += vm_ops_fault_removed_vma_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_atomic_helper_crtc_destroy_state_has_crtc_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_atomic_helper_plane_destroy_state_has_plane_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_mode_object_find_has_file_priv_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += dma_buf_owner
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_connector_list_iter
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_atomic_helper_swap_state_has_stall_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_prime_flag_present
NV_CONFTEST_TYPE_COMPILE_TESTS += vm_fault_t
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_gem_object_has_resv
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_crtc_state_has_async_flip
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_crtc_state_has_pageflip_flags
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_crtc_state_has_vrr_enabled
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_format_modifiers_present
NV_CONFTEST_TYPE_COMPILE_TESTS += mm_has_mmap_lock
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_vma_node_is_allowed_has_tag_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_vma_offset_node_has_readonly
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_display_mode_has_vrefresh
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_master_set_has_int_return_type
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_has_gem_free_object
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_prime_pages_to_sg_has_drm_device_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_has_gem_prime_callbacks
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_crtc_atomic_check_has_atomic_state_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_gem_object_vmap_has_map_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_plane_atomic_check_has_atomic_state_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_device_has_pdev
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_crtc_state_has_no_vblank
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_mode_config_has_allow_fb_modifiers
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_has_hdr_output_metadata
NV_CONFTEST_TYPE_COMPILE_TESTS += dma_resv_add_fence
NV_CONFTEST_TYPE_COMPILE_TESTS += dma_resv_reserve_fences
NV_CONFTEST_TYPE_COMPILE_TESTS += reservation_object_reserve_shared_has_num_fences_arg
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_connector_has_override_edid
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_master_has_leases
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_file_get_master
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_modeset_lock_all_end
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_connector_lookup
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_connector_put
NV_CONFTEST_TYPE_COMPILE_TESTS += vm_area_struct_has_const_vm_flags
NV_CONFTEST_TYPE_COMPILE_TESTS += drm_driver_has_dumb_destroy

conftest/type.h: ${PWD}/conftest.sh ${DRMKMODDIR}
	mkdir -p conftest
	${PWD}/conftest.sh '${CC}' x86_64 ${DRMKMODDIR} this_arg_not_used_on_bsd compile_tests '${NV_CONFTEST_CFLAGS}' ${NV_CONFTEST_TYPE_COMPILE_TESTS} > conftest/type.h

CONFTEST_FILES = conftest/generic.h conftest/function.h conftest/type.h

${CONFTEST_FILES}: conftest/headers.h

*.c: ${CONFTEST_FILES}
*.h: ${CONFTEST_FILES}

clean:
	rm -rf conftest

.include <bsd.kmod.mk>

