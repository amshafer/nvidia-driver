.if defined(LIB) && defined(SHLIB_MAJOR)
SHLIB_NAME?=	lib${LIB}.so.${SHLIB_MAJOR}
.endif
.if defined(SHLIB_NAME)
.if !defined(SHLIB_NO_LINK)
SHLIB_LINK?=	${SHLIB_NAME:R}
.endif
.if defined(AUXLINK_LINK)
AUXLINK_TGT?=${AUXLINK_TGT_DIR}${SHLIB_NAME}
.endif
.endif
.if defined(STATIC_LIB) && ${STATIC_LIB} == "true"
STATICLIB_NAME?=     lib${LIB}.a
.endif

.if !defined(OBJDIR)
OBJDIR=		obj
.endif

LIBANDOBJDIRS=	${LIBDIR} ${OBJDIR}
.if exists(${NVIDIA_ROOT}/${OBJDIR}/32/${SHLIB_NAME})
LIBANDOBJDIRS+=	${LIBDIR:S/\/lib/\/lib32/} ${OBJDIR}/32
.endif

all:   # dummy rule
clean: # dummy rule

install: ${EXTRADEPS}
.for THISLIBDIR THISOBJDIR in ${LIBANDOBJDIRS}
.if defined(SHLIB_NAME)
	@mkdir -p ${DESTDIR}${THISLIBDIR}
	@rm -f ${DESTDIR}${THISLIBDIR}/${SHLIB_NAME}
	@${INSTALL} -C -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
		${NVIDIA_ROOT}/${THISOBJDIR}/${SHLIB_NAME} \
		${DESTDIR}${THISLIBDIR}
.endif
.if defined(SHLIB_LINK)
# If SHLIB_LINK_NOCLOBBER is defined, any symlinks will be removed (and a
# symlink to our library added), but regular files will not be removed.
.if defined(SHLIB_LINK_NOCLOBBER)
	@if [ ! -e ${DESTDIR}${THISLIBDIR}/${SHLIB_LINK} ] || \
		[ -L ${DESTDIR}${THISLIBDIR}/${SHLIB_LINK} ]; then \
	    rm -f ${DESTDIR}${THISLIBDIR}/${SHLIB_LINK}; \
	    ln -fs ${SHLIB_NAME} ${DESTDIR}${THISLIBDIR}/${SHLIB_LINK}; \
	else \
	    echo "Note: Not installing a symlink to ${SHLIB_NAME} "; \
	    echo "because ${DESTDIR}${THISLIBDIR}/${SHLIB_LINK} already exists."; \
	fi
.else
	@rm -f ${DESTDIR}${THISLIBDIR}/${SHLIB_LINK}
	@ln -fs ${SHLIB_NAME} ${DESTDIR}${THISLIBDIR}/${SHLIB_LINK}
.endif
.endif
.if defined(AUXLINK_TGT)
	@rm -f ${AUXLINK_LINK}
	@ln -fs ${AUXLINK_TGT} ${AUXLINK_LINK}
.endif
.if defined(STATICLIB_NAME)
	@rm -f ${DESTDIR}${THISLIBDIR}/${STATICLIB_NAME}
	@${INSTALL} -C -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
		${NVIDIA_ROOT}/${THISOBJDIR}/${STATICLIB_NAME} \
		${DESTDIR}${THISLIBDIR}
.endif
.endfor

.include <bsd.init.mk>
