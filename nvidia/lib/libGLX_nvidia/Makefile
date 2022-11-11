NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

LIB=		GLX_nvidia
SHLIB_MAJOR=	0
LIBDIR=		${LOCALBASE}/lib
AUXLINK_LINK=   ${DESTDIR}${LIBDIR}/libGLX_indirect.so.0
AUXLINK_TGT_DIR=

EXTRADEPS=	nvidia-application-profiles-rc nvidia_icd.json nvidia_layers.json

# XXX /usr/share/nvidia path hardcoded, because that's where libGL will
# look for this file.

nvidia_icd.json:
	@mkdir -p ${VKICD_PATH}
	@${INSTALL} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
		${NVIDIA_ROOT}/nvidia_icd.json \
		${VKICD_PATH}
	@sed -i '' -e "s/__NV_VK_ICD__/lib${LIB}.so/" ${VKICD_PATH}/nvidia_icd.json

nvidia_layers.json:
	@mkdir -p ${VKLAYERS_PATH}
	@${INSTALL} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
		${NVIDIA_ROOT}/nvidia_layers.json \
		${VKLAYERS_PATH}
	@sed -i '' -e "s/__NV_VK_ICD__/lib${LIB}.so/" ${VKLAYERS_PATH}/nvidia_layers.json


nvidia-application-profiles-rc:
	@mkdir -p /usr/share/nvidia
	@${INSTALL} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	${NVIDIA_ROOT}/obj/nvidia-application-profiles-rc \
	/usr/share/nvidia	

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>
