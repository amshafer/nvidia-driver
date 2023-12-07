#
# This Makefile was automatically generated; do not edit.
#

OSOBJ=		nv-freebsd.o
KMOD=		nvidia
RMOBJ=		nv-kernel.o

KMODDIR?=	/boot/modules

SPECTRE_V2_RETPOLINE?=	1

include nvidia-sources.mk

SRCS=		${NVIDIA_SOURCES}
SRCS+=		acpi_if.h bus_if.h device_if.h opt_acpi.h pci_if.h vnode_if.h
CFLAGS+=	-I. -I../common/inc -DNV_VERSION_STRING=\"535.129.03\"
CFLAGS+=	-D__KERNEL__ -DNVRM  -Wno-unused-function -Wuninitialized -O2 -fno-strict-aliasing    -ffreestanding -mno-red-zone -mcmodel=kernel       -UDEBUG -U_DEBUG -DNDEBUG
CFLAGS+=	-DNV_SPECTRE_V2=$(SPECTRE_V2_RETPOLINE)
CFLAGS+=	-DNV_KERNEL_INTERFACE_LAYER

include ../common/optional-cflags.mk

OBJS+=		${RMOBJ}
NO_OBJ=		true

stdarg.h:
	@ln -s machine/stdarg.h stdarg.h

*.c: stdarg.h

beforeinstall:	${KMOD}.ko

all:	${OSOBJ}

${OSOBJ}:	${KMOD}.ko
	@${LD} -r -o $@ ${OBJS:S/${RMOBJ}//}

CLEANFILES+=	${OSOBJ}

clean:
	@rm -f ${CLEANFILES:S/${RMOBJ}//}
	@rm -f stdarg.h

.include <bsd.kmod.mk>
