NVIDIA_ROOT=    ${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

DRIVERS=	nvidia_drv.o nvidia_drv.so
.if exists(${LOCALBASE}/lib/xorg/modules/drivers)
DRIVERDIR=	${LOCALBASE}/lib/xorg/modules/drivers
.else
DRIVERDIR=	${LOCALBASE}/lib/modules/drivers
.endif

all:   # dummy rule
clean: # dummy rule

install:
	@for __driver in ${DRIVERS}; do \
		rm -f ${DESTDIR}${DRIVERDIR}/$${__driver} ; \
	done
	@${INSTALL} -C -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
		${NVIDIA_ROOT}/obj/nvidia_drv.so \
		${DESTDIR}${DRIVERDIR} ; \

.include <bsd.init.mk>
