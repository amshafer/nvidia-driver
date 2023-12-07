SRCS = nvidia-modeset-freebsd.c
KMOD = nvidia-modeset

KMODDIR ?= /boot/modules

NVIDIA_MODESET_KERNEL = nv-modeset-kernel.o

OBJS += ${NVIDIA_MODESET_KERNEL}
NO_OBJ = true

clean:
	@rm -f ${CLEANFILES:S/${NVIDIA_MODESET_KERNEL}//}

beforeinstall:  ${KMOD}.ko

# So that the build can include machine/stdarg.h
CFLAGS += -Imachine

# So that the build can include sys/stddef.h
CFLAGS += -I${SYSDIR}/sys

CFLAGS += -I../common/inc
CFLAGS += -DNV_VERSION_STRING=\"535.129.03\"

SPECTRE_V2_RETPOLINE ?= 1
CFLAGS += -DNV_SPECTRE_V2=$(SPECTRE_V2_RETPOLINE)

include ../common/optional-cflags.mk

.include <bsd.kmod.mk>
