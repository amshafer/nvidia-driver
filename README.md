# nvidia-driver

This is a version of FreeBSD's nvidia driver which contains
nvidia-drm.ko, normally a linux only kernel module.

## Progress

At the moment this can run anything that displays *only using
libdrm*. If it uses EGL (like kmscube) it will not work.

## Relevant Links
* https://badland.io/nvidia-drm.md
* https://badland.io/nvidia.md

## Warning
This is highly unstable, and not that useful. Please do not use this
for anything important.

## Compiling

You will need to download and build the FreeBSD source and the kms-drm code for
(Ideally version 5.0 or higher). You will also need to change
the include directories specified in `src/nvidia-drm/Makefile` to
match where you've built kms-drm. After that you can just type `make
install`. Make sure to install kms-drm as well.

*note* - This requires a GENERIC-NODEBUG kernel. The nvidia
 locks will panic if witness is enabled.
