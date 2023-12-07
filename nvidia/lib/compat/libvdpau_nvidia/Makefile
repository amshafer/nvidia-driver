NVIDIA_ROOT=	${.CURDIR}/../../..

LIB=		vdpau_nvidia
SHLIB_VERSION=	535.129.03
SHLIB_NAME=	lib${LIB}.so.${SHLIB_VERSION}
SHLIB_LINK=	lib${LIB}.so.1
BASELIBDIR=     /compat/linux/usr/lib
LIBDIR=		${BASELIBDIR}/vdpau
OBJDIR=		obj/linux

AUXLINK_LINK=${BASELIBDIR}/lib${LIB}.so
AUXLINK_TGT_DIR=vdpau/

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>
