NVIDIA_ROOT=	${.CURDIR}/..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

BSDVER!=	/sbin/sysctl -n kern.osreldate
NO_OBJ=	noobj

DOCS=	README \
	XF86Config.sample \
	license.txt

htmlDOCS!=(ls ${NVIDIA_ROOT}/doc/html/)
supported-gpusDOCS!=(ls ${NVIDIA_ROOT}/doc/supported-gpus/)

DOCDIR=	${LOCALBASE}/share/doc/NVIDIA_GLX-1.0

all:   # dummy rule
clean: # dummy rule

install:
	@mkdir -p ${DESTDIR}${DOCDIR}
.for doc in ${DOCS}
	@${INSTALL} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${NVIDIA_ROOT}/doc/${doc} \
		${DESTDIR}${DOCDIR}
.endfor
.for subdir in html supported-gpus
	@mkdir -p ${DESTDIR}${DOCDIR}/${subdir}
.for doc in ${${subdir}DOCS}
	@${INSTALL} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${NVIDIA_ROOT}/doc/${subdir}/${doc} \
		${DESTDIR}${DOCDIR}/${subdir}
.endfor
.endfor
# XXX /usr/share/nvidia path hardcoded because that's where nvidia-settings
# will look for this file.
	@mkdir -p /usr/share/nvidia
	@${INSTALL} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${NVIDIA_ROOT}/doc/nvidia-application-profiles-key-documentation \
		/usr/share/nvidia
.include <bsd.prog.mk>
