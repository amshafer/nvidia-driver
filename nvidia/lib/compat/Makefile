
.if !defined(INSTALL_COMPAT_LIBGLVND_SNAPSHOT)
INSTALL_COMPAT_LIBGLVND_SNAPSHOT= 0
.endif

SUBDIR= libGLX_nvidia	\
	libnvidia-tls	\
	libnvidia-glcore \
	libvdpau_nvidia \
	libcuda \
	libnvidia-glvkspirv

.if exists(libnvidia-eglcore)
SUBDIR+=	libnvidia-eglcore	\
		libnvidia-glsi
.endif

.if exists(libEGL_nvidia)
SUBDIR+=	libEGL_nvidia
SUBDIR+=	libGLESv2_nvidia
SUBDIR+=	libGLESv1_CM_nvidia
.endif

.if $(INSTALL_COMPAT_LIBGLVND_SNAPSHOT)
SUBDIR+= libGL		\
	 libGLX

.if exists(libEGL)
SUBDIR+= libEGL
.endif
.if exists(libGLESv2)
SUBDIR+= libGLESv2
.endif
.if exists(libGLESv1_CM)
SUBDIR+= libGLESv1_CM
.endif
.if exists(libGLdispatch)
SUBDIR+= libGLdispatch
.endif
.if exists(libOpenGL)
SUBDIR+= libOpenGL
.endif
.endif


.include <bsd.subdir.mk>
