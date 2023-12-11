NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

LIB=		vdpau_nvidia
SHLIB_MAJOR=	1
SHLIB_NO_LINK=1
BASELIBDIR=     ${LOCALBASE}/lib
LIBDIR=		${BASELIBDIR}/vdpau

AUXLINK_LINK=${BASELIBDIR}/lib${LIB}.so
AUXLINK_TGT_DIR=vdpau/

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>
