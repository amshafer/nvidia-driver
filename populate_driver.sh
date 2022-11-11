#!/bin/sh
#
# This script will populate the nvidia folder with the unmodified 
# driver files. This script is required because we need to do a couple
# things:
#
# 1) grab both the FreeBSD and Linux nvidia driver packages and
#    extract them.
# 2) Copy the nvidia-drm source files to the src/nvidia-drm directory
# 3) Copy the conftest.sh file to src/nvidia-drm/conftest.sh
#
# These steps are needed because the nvidia-drm source files are not
# shipped in the FreeBSD driver. This script will populate the target
# directory, so that patches can be applied to the nvidia-drm source.

if [ "$#" -ne 1 ]; then
    echo "Usage: ./populate_driver.sh <Nvidia driver version>"
    echo "       example: ./populate_driver.sh 520.56.06"
    exit 1
fi

# check that we are in the right directory
if ! [ -d "nvidia" ]; then
    echo "ERROR: Could not find 'nvidia' directory, please run from root of nvidia-driver repo"
    exit 1
fi

# Our only argument is the version number (XXX.XX.XX) of the driver to populate
NVVERSION=$1

TMPDIR=`mktemp -d -t nvidia-driver`

echo "Fetching driver files for ${NVVERSION}..."

# FreeBSD download links look like this:
# http://us.download.nvidia.com/XFree86/FreeBSD-x86_64/520.56.06/NVIDIA-FreeBSD-x86_64-520.56.06.tar.xz
FREEBSD_DRIVER_NAME="NVIDIA-FreeBSD-x86_64-${NVVERSION}"
FREEBSD_DRIVER_LINK="http://us.download.nvidia.com/XFree86/FreeBSD-x86_64/${NVVERSION}/${FREEBSD_DRIVER_NAME}.tar.xz"
if ! fetch ${FREEBSD_DRIVER_LINK} -o ${TMPDIR} ; then
    echo "ERROR: Could not fetch Nvidia FreeBSD driver file ${FREEBSD_DRIVER_LINK}"
    rm -rf ${TMPDIR}
    exit 1
fi

if ! tar xvzf ${TMPDIR}/${FREEBSD_DRIVER_NAME}.tar.xz -C ./nvidia --strip-components 1 ; then
    echo "ERROR: Could not extract Nvidia FreeBSD driver file"
    rm -rf ${TMPDIR}
    exit 1
fi

# Extract the FreeBSD files into the nvidia directory

# Linux download links look like this:
# https://us.download.nvidia.com/XFree86/Linux-x86_64/520.56.06/NVIDIA-Linux-x86_64-520.56.06.run
LINUX_DRIVER_NAME="NVIDIA-Linux-x86_64-${NVVERSION}"
LINUX_DRIVER_LINK="http://us.download.nvidia.com/XFree86/Linux-x86_64/${NVVERSION}/${LINUX_DRIVER_NAME}.run"
LINUX_DRIVER_DIR="${TMPDIR}/${LINUX_DRIVER_NAME}"
if ! fetch ${LINUX_DRIVER_LINK} -o ${TMPDIR} ; then
    echo "ERROR: Could not fetch Nvidia Linux driver file ${LINUX_DRIVER_LINK}"
    rm -rf ${TMPDIR}
    exit 1
fi

# extract the Linux files in our temporary location
chmod +x ${TMPDIR}/${LINUX_DRIVER_NAME}.run
if ! ${TMPDIR}/${LINUX_DRIVER_NAME}.run --extract-only --target ${LINUX_DRIVER_DIR} ; then
    echo "ERROR: Could not extract Nvidia Linux driver file"
    rm -rf ${TMPDIR}
    exit 1
fi

echo "Copying DRM files into ./nvidia/src/nvidia-drm ..."

# Copy nvidia-drm files
cp -r ${LINUX_DRIVER_DIR}/kernel/nvidia-drm ./nvidia/src/

# Copy conftest and Linux files
cp ${LINUX_DRIVER_DIR}/kernel/conftest.sh ./nvidia/src/nvidia-drm/
cp ${LINUX_DRIVER_DIR}/kernel/nvidia/nv-pci-table.* ./nvidia/src/nvidia-drm/

# Touch any files that we want to add during the patching phase. We
# need them to be present in the git history
touch ./nvidia/src/nvidia-drm/Makefile
touch ./nvidia/src/nvidia-drm/nvidia-drm-freebsd-lkpi.c

# clean up our environment
rm -rf ${TMPDIR}

echo "-------------------------------------------------------------"
echo "| ./nvidia has been populated with Nvidia driver ${NVVERSION}  |"
echo "-------------------------------------------------------------"
