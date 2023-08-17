NVIDIA_ROOT=    ${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

LIB=		glxserver_nvidia
SHLIB_MAJOR=	1
.if exists(${LOCALBASE}/lib/xorg/modules/extensions)
LIBDIR=		${LOCALBASE}/lib/xorg/modules/extensions
.else
LIBDIR=		${LOCALBASE}/lib/modules/extensions
.endif

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>
