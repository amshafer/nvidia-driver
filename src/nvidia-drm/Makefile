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
	nvidia-dma-fence-helper.h \
	nvidia-drm-connector.h \
	nvidia-drm-crtc.h \
	nvidia-drm-drv.h \
	nvidia-drm-encoder.h \
	nvidia-drm-fb.h \
	nvidia-drm-gem-nvkms-memory.h \
	nvidia-drm-gem-user-memory.h \
	nvidia-drm-gem.h \
	nvidia-drm-helper.h \
	nvidia-drm-ioctl.h \
	nvidia-drm-modeset.h \
	nvidia-drm-os-interface.h \
	nvidia-drm-prime-fence.h \
	nvidia-drm-priv.h \
	nvidia-drm-utils.h \
	nvidia-drm.h

SRCS += \
	nvidia-drm-connector.c \
	nv-pci-table.c \
	nvidia-drm-crtc.c \
	nvidia-drm-drv.c \
	nvidia-drm-encoder.c \
	nvidia-drm-fb.c \
	nvidia-drm-gem-nvkms-memory.c \
	nvidia-drm-gem-user-memory.c \
	nvidia-drm-gem.c \
	nvidia-drm-helper.c \
	nvidia-drm-freebsd-lkpi.c \
	nvidia-drm-modeset.c \
	nvidia-drm-prime-fence.c \
	nvidia-drm-utils.c \
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

CFLAGS += -g -I/usr/include -I../common/inc -O0 -Wno-visibility
# FreeBSD linuxkpi specific headers
CFLAGS += \
        -I/home/ashafer/git/kms-drm/linuxkpi/gplv2/include/ \
        -I/usr/src/sys/compat/linuxkpi/common/include/ \
        -I/home/ashafer/git/kms-drm/linuxkpi/dummy/include/ \
        -I/home/ashafer/git/kms-drm/include/ \
        -I/home/ashafer/git/kms-drm/include/uapi/ \
        -I/home/ashafer/git/kms-drm/drivers/gpu/

# make sure /usr/include is before all the other includes
#CFLAGS = "-I/usr/include/ $CFLAGS"

CFLAGS += -DNV_VERSION_STRING=\"440.82\"

include ../common/optional-cflags.mk

# we need to get the linux kpi headers for compilation. BSDSRCTOP
# is the top of a FreeBSD src tree (or empty to use /sys)
BSDSRCTOP=/usr/src
CFLAGS+= -I${BSDSRCTOP}/sys/compat/linuxkpi/common/include
CFLAGS+= -I${BSDSRCTOP}/sys/contrib/ck/include

# add src/nvidia as we need headers from there for nvidia_softc
# we use the softc to get the device_t during probing
CFLAGS+= -I../nvidia/

.include <bsd.kmod.mk>
