NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

MANDIR=	${LOCALBASE}/man/man1

all:   # dummy rule
clean: # dummy rule

install:
	@${INSTALL} -o ${MANOWN} -g ${MANGRP} -m ${MANMODE} \
		${NVIDIA_ROOT}/nvml/man/nvidia-smi.1 \
		${DESTDIR}${MANDIR}

.include <bsd.init.mk>
