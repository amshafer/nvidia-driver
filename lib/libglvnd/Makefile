.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

SUBDIR=		libGL \
		libGLdispatch \
		libGLX \
		libOpenGL

.if exists(../libEGL_nvidia)
SUBDIR+=	libEGL \
		libGLESv1_CM \
		libGLESv2
.endif

.include <bsd.subdir.mk>
