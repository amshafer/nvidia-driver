NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

BSDVER!=	/sbin/sysctl -n kern.osreldate
NO_OBJ=	noobj

BINDIR=	${LOCALBASE}/bin

install:
	@${INSTALL} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${NVIDIA_ROOT}/obj/nvidia-settings \
		${DESTDIR}${BINDIR}
	@${INSTALL} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${NVIDIA_ROOT}/obj/nvidia-xconfig \
		${DESTDIR}${BINDIR}
	@${INSTALL} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${NVIDIA_ROOT}/obj/nvidia-bug-report.sh \
		${DESTDIR}${BINDIR}

.include <bsd.prog.mk>
