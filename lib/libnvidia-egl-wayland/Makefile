NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

LIB=		nvidia-egl-wayland
SHLIB_MAJOR=	1
LIBDIR=		${LOCALBASE}/lib

EXTRADEPS=	10_nvidia_wayland.json

10_nvidia_wayland.json:
	@mkdir -p $(EGL_WAYLAND_JSON_PATH)
	@${INSTALL} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	${NVIDIA_ROOT}/obj/10_nvidia_wayland.json \
	$(EGL_WAYLAND_JSON_PATH)

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>
