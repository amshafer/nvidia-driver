NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

MANDIR=	${LOCALBASE}/man/man1

all:   # dummy rule
clean: # dummy rule

install:
	@${INSTALL} -o ${MANOWN} -g ${MANGRP} -m ${MANMODE} \
		${NVIDIA_ROOT}/x11/man/nvidia-settings.1 \
		${DESTDIR}${MANDIR}
	@${INSTALL} -o ${MANOWN} -g ${MANGRP} -m ${MANMODE} \
		${NVIDIA_ROOT}/x11/man/nvidia-xconfig.1 \
		${DESTDIR}${MANDIR}

.include <bsd.init.mk>
