NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

LIB=		nvidia-egl-gbm
SHLIB_MAJOR=	1
LIBDIR=		${LOCALBASE}/lib

EXTRADEPS=	15_nvidia_gbm.json

15_nvidia_gbm.json:
	@mkdir -p $(EGL_EXTERNAL_PLATFORM_JSON_PATH)
	@${INSTALL} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	${NVIDIA_ROOT}/obj/15_nvidia_gbm.json \
	$(EGL_EXTERNAL_PLATFORM_JSON_PATH)

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>
