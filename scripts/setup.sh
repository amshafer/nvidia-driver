#!/bin/sh

srcdir="$1"
if [ ! -d "${srcdir}" ] ; then
    echo "$0: ERROR: First argument must be source directory"
    exit 1
fi

unload_module()
{
    _module=$1
    kldstat -n ${_module} > /dev/null 2>&1; RESULT=$?
    if [ ${RESULT} -eq 0 ]; then
        kldunload -n ${_module} > /dev/null 2>&1; RESULT=$?
        if [ ${RESULT} -ne 0 ]; then
            echo 'ERROR: Failed to unload the ${_module} module!'
            echo 'ERROR: Is ${_module}.ko in use?'
            exit 1;
        fi
    fi
}

module_exists_in_package()
{
    _module=$1

    [ -d "${srcdir}/${_module}" ]
}

load_module()
{
    _module=$1

    if ! module_exists_in_package "${_module}"; then
        return
    fi
    kldload ${_module} > /dev/null 2>&1 ; RESULT=$?
    if [ ${RESULT} -ne 0 ]; then
        echo 'ERROR: Failed to load the ${_module} module!'
        exit 1;
    fi
}

load_module_on_boot()
{
    _prefix=$1
    _module=$2

    if ! module_exists_in_package "${_module}"; then
        return
    fi

    # Remove any lines that will be added below
    sed -e /${_prefix}_load=.*/d -i.orig /boot/loader.conf
    sed -e /${_prefix}_name=\"${_module}\"/d -i.orig /boot/loader.conf

    echo ${_prefix}_load=\"YES\" >> /boot/loader.conf
    echo ${_prefix}_name=\"${_module}\" >> /boot/loader.conf
}

unload_module "nvidia-modeset"
unload_module "nvidia"

load_module "nvidia"
load_module "nvidia-modeset"

load_module_on_boot "nvidia" "nvidia"
load_module_on_boot "nvidia_modeset" "nvidia-modeset"

