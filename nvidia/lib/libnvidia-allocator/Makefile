NVIDIA_ROOT=    ${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=      /usr/local
.endif

LIB=            nvidia-allocator
SHLIB_MAJOR=    1
LIBDIR=         ${LOCALBASE}/lib

EXTRADEPS = nvidia-drm_gbm.so

# make a symlink for gbm stuff at
# /usr/local/lib/gbm/nvidia-drm_gbm.so
nvidia-drm_gbm.so:
	@mkdir -p ${LOCALBASE}/lib/gbm/
	ln -sf ${LOCALBASE}/lib/libnvidia-allocator.so.1 ${LOCALBASE}/lib/gbm/nvidia-drm_gbm.so

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>

