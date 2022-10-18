SUBDIR= nvidia

.if exists(nvidia-modeset)
SUBDIR+= nvidia-modeset
.endif

.if exists(nvidia-drm)
SUBDIR+= nvidia-drm
.endif

setup:  install

.include <bsd.subdir.mk>
