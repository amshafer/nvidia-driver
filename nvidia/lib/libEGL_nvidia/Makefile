NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

LIB=		EGL_nvidia
SHLIB_MAJOR=	0
LIBDIR=		${LOCALBASE}/lib

EXTRADEPS=	10_nvidia.json

10_nvidia.json:
	@mkdir -p $(EGL_GLVND_JSON_PATH)
	@${INSTALL} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	${NVIDIA_ROOT}/obj/10_nvidia.json \
	$(EGL_GLVND_JSON_PATH)

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>
