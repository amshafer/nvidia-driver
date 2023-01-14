.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

SUBDIR=
FIND_FILES_ARGS=


.if exists(libglvnd)
.if !defined(INSTALL_LIBGLVND_SNAPSHOT)
# Run pkg-config to see if the libglvnd libraries are already installed.
INSTALL_LIBGLVND_SNAPSHOT!= (if pkg-config --atleast-version=1.0.0 libglvnd 2> /dev/null ; then echo 0 ; else echo 1 ; fi)
.endif
.else
INSTALL_LIBGLVND_SNAPSHOT= 0
.endif

.if exists(libglvnd) && $(INSTALL_LIBGLVND_SNAPSHOT)
SUBDIR += libglvnd
FIND_FILES_ARGS+= \
		-name libGLdispatch.a\* -or \
		-name libGLdispatch.so\* -or \
		-name libOpenGL.a\* -or \
		-name libOpenGL.so\* -or \
		-name libGL.a\* -or \
		-name libGL.so\* -or \
		-name libGLX.a\* -or \
		-name libGLX.so\* -or
.if exists(libEGL_nvidia)
FIND_FILES_ARGS+= \
		-name libEGL.\* -or \
		-name libGLESv2.\* -or \
		-name libGLESv1_CM.\* -or
EGL_GLVND_JSON_PATH ?= /usr/share/glvnd/egl_vendor.d/
.endif
.endif

.if exists(libGLX_nvidia)
SUBDIR+=	libGLX_nvidia
FIND_FILES_ARGS+= \
		-name libGLX_nvidia.a\* -or \
		-name libGLX_nvidia.so\* -or \
		-name libglxserver_nvidia.\* -or 
.else
SUBDIR +=	libGL
FIND_FILES_ARGS += \
		-name libGL.a\* -or \
		-name libGL.so\* -or \
		-name libglx.\* -or
.endif

SUBDIR+= 	libnvidia-tls	\
		libnvidia-cfg	\
		libnvidia-glcore	\
		libnvidia-gtk2  \
		libnvidia-gtk3  \
		libnvidia-wayland-client \
		libvdpau_nvidia	\
		libnvidia-glvkspirv \
		libnvidia-vulkan-producer

.if exists(libnvidia-eglcore)
SUBDIR+=	libnvidia-eglcore	\
		libnvidia-glsi
FIND_FILES_ARGS += \
		-name libnvidia-eglcore.\* -or \
		-name libnvidia-glsi.\* -or
.if exists(libEGL_nvidia)
SUBDIR+=	libEGL_nvidia \
		libGLESv2_nvidia \
		libGLESv1_CM_nvidia
FIND_FILES_ARGS += \
		-name libEGL_nvidia.\* -or \
		-name libGLESv2_nvidia.\* -or \
		-name libGLESv1_CM_nvidia.\* -or

# Try to figure out where the libglvnd EGL JSON file should go.
.if !defined(EGL_GLVND_JSON_PATH)
EGL_GLVND_JSON_PATH!= pkg-config --variable=datadir libglvnd 2> /dev/null
.if empty(EGL_GLVND_JSON_PATH)
# pkg-config didn't find anything, so pick a plausible default.
EGL_GLVND_JSON_PATH= /usr/share
.endif
EGL_GLVND_JSON_PATH:= $(EGL_GLVND_JSON_PATH)/glvnd/egl_vendor.d
.endif
.export EGL_GLVND_JSON_PATH

.else
SUBDIR+=	libEGL \
		libGLESv2 \
		libGLESv1_CM
FIND_FILES_ARGS += \
		-name libEGL.\* -or \
		-name libGLESv2.\* -or \
		-name libGLESv1_CM.\* -or
.endif
.endif

.if exists(libnvidia-egl-wayland)
SUBDIR +=	libnvidia-egl-wayland
FIND_FILES_ARGS += \
		-name libnvidia-egl-wayland.so\* -or

# Try to figure out where the wayland EGL JSON file should go.
.if !defined(EGL_EXTERNAL_PLATFORM_JSON_PATH)
EGL_EXTERNAL_PLATFORM_JSON_PATH:= /usr/share/egl/egl_external_platform.d
.endif
.export EGL_EXTERNAL_PLATFORM_JSON_PATH
.endif

.if exists(libnvidia-ml)
SUBDIR+=	libnvidia-ml
.endif

.if exists(libnvidia-egl-gbm)
SUBDIR+=	libnvidia-egl-gbm
.endif

.if exists(libnvidia-allocator)
SUBDIR+=	libnvidia-allocator
.endif

FIND_DIRS=	/usr/lib	\
		${LOCALBASE}/lib

.if exists(/compat/linux)
SUBDIR+=	compat
FIND_DIRS+=	/compat/linux/lib \
		/compat/linux/usr/lib \
		/compat/linux/usr/X11R6/lib
.endif

FIND_FILES!=(find ${FIND_DIRS} \
		$(FIND_FILES_ARGS) \
		-name libnvidia-tls.so\* -or \
		-name libnvidia-cfg.so\* -or \
		-name libnvidia-glcore.\* -or \
		-name libnvidia-gtk2.\* -or \
		-name libnvidia-gtk3.\* -or \
		-name libnvidia-wayland-client.\* -or \
		-name libvdpau_nvidia.\* \
		| xargs ${ECHO})

.if exists(libGLX_nvidia)
# The NVIDIA GLX server module is now named libglxserver_nvidia.so instead of
# libglx.so. If the existing libglx.so module is from an previous NVIDIA
# installation, then remove it so that we don't get a version mismatch with the
# rest of the driver.
FIND_NV_LIBGLX!=(find -P ${FIND_DIRS} \
		-type f \
		-name libglx.\* \
		| xargs ${ECHO})

FIND_NV_LIBGLX_SYMLINKS!=(find -P ${FIND_DIRS} \
		-type l \
		-name libglx.\* \
		| xargs ${ECHO})

VKICD_PATH ?= /usr/local/share/vulkan/icd.d
.export VKICD_PATH
VKLAYERS_PATH ?= /usr/local/share/vulkan/implicit_layer.d
.export VKLAYERS_PATH

.else
FIND_NV_LIBGLX=
FIND_NV_LIBGLX_SYMLINKS=
.endif

DATE=`date "+%Y%m%d"`

GREP=/usr/bin/grep
ECHO=/usr/bin/true

beforeinstall:
	@-for __file in ${FIND_NV_LIBGLX_SYMLINKS} ${FIND_NV_LIBGLX}; do \
		${ECHO} "===> Checking file: $${__file}" ; \
		if [ ! -e $${__file} ] ; then \
			${ECHO} "	- File does not exist." ; \
			continue ; \
		fi ; \
		${GREP} 'nvidia id:' $${__file} > /dev/null 2>&1 ; RESULT=$$? ; \
		if [ $${RESULT} -eq 0 ] ; then \
			${ECHO} "	- File has NVIDIA signature, removing." ; \
			rm -f $${__file} ; \
			continue ; \
		fi ; \
	done
	@-for __file in ${FIND_FILES}; do \
		${ECHO} "===> Checking file: $${__file}" ; \
		if [ -L $${__file} ] ; then \
			${ECHO} "	- File is a symlink, removing." ; \
			rm -f $${__file} ; \
			continue ; \
		fi ; \
		if [ ! -e $${__file} ] ; then \
			${ECHO} "	- File does not exist." ; \
			continue ; \
		fi ; \
		${GREP} 'nvidia id:' $${__file} > /dev/null 2>&1 ; RESULT=$$? ; \
		if [ $${RESULT} -eq 0 ] ; then \
			${ECHO} "	- File has NVIDIA signature, removing." ; \
			rm -f $${__file} ; \
			continue ; \
		fi ; \
		SUFFIX=`pkg which -q $${__file}` ; RESULT=$$? ; \
		if [ -n "$${SUFFIX}" ] ; then \
			${ECHO} "	- File was installed by package $${SUFFIX}" ; \
		else \
			${ECHO} "	- File is unknown or orphaned." ; \
			SUFFIX="orig-${DATE}" ; \
		fi ; \
		${ECHO} "	- Creating backup." ; \
		FILE_NAME=`basename $${__file}` ; \
		DIR_NAME=`dirname $${__file}` ; \
		mv -f $${__file} $${DIR_NAME}/XXX-$${FILE_NAME}.%%.$${SUFFIX} ; \
	done

.include <bsd.subdir.mk>
