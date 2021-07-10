SUBDIR= libGL		\
	libGLX		\
	libGLX_nvidia	\
	libnvidia-tls	\
	libnvidia-glcore \
	libvdpau_nvidia \
	libcuda \
	libnvidia-glvkspirv

.if exists(libnvidia-eglcore)
SUBDIR+=	libnvidia-eglcore	\
		libnvidia-glsi		\
		libEGL			\
		libGLESv2		\
		libGLESv1_CM
.endif

.if exists(libEGL_nvidia)
SUBDIR+=	libEGL_nvidia
SUBDIR+=	libGLESv2_nvidia
SUBDIR+=	libGLESv1_CM_nvidia
.endif

.if exists(libGLdispatch)
SUBDIR+=	libGLdispatch
.endif

.if exists(libOpenGL)
SUBDIR+=	libOpenGL
.endif

.include <bsd.subdir.mk>
