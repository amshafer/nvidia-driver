# FreeBSD Nvidia DRM driver

This is a port of Linux's `nvidia-drm.ko` that interfaces with the DRM
subsystem. FreeBSD has a Linux kernel compatibility layer which nvidia-drm can
be modified to run on. This repository packages the base FreeBSD driver files
with the Linux driver's nvidia-drm source files (with FreeBSD patches applied).
The resulting driver can be found in the `nvidia` subdirectory.

The most important use case of this is Wayland compositors. Namely, a sway
desktop is fully usable on Nvidia hardware when running with this driver. Wayland
compositors primarily use the DRM-KMS api for advanced display features and
for importing GPU buffers from clients without performing a copy.

Development in this repository goes towards two versions in the FreeBSD ports tree: 

* [graphics/nvidia-drm-510-kmod](https://www.freshports.org/graphics/nvidia-drm-510-kmod/) compatible with drm.ko 5.10
* [graphics/nvidia-drm-515-kmod](https://www.freshports.org/graphics/nvidia-drm-515-kmod/) compatible with drm.ko 5.15.

The **meta port**, which automatically installs a recommended version of the driver, will suit most use cases:

* [graphics/nvidia-drm-kmod](https://www.freshports.org/graphics/nvidia-drm-kmod/).

## Branch Structure

All infrastructure and patches are contained in the `baseline` branch. This has
a driver source code applied on top of it, which the patches are then applied
to. Branch names are always the version number of the driver they contain. i.e.
if you want a `525.XX.X` driver check out the `525.XX.X` branch.

Please note that 525 is the first driver series with full `nvidia-drm` support,
drivers that predate this lack the closed-source Nvidia changes necessary.

## Dependencies

There are two main things that this driver is dependent on: the FreeBSD src
tree and the [drm-kmod](https://github.com/freebsd/drm-kmod) port. The normal
FreeBSD nvidia driver is dependent on the source tree, but `drm-kmod` is new.

To make this easier there are two variables you can override to set the
reference locations:
* `BSDSRCTOP` - defaults to `/usr/src`
* `DRMKMODDIR` - defaults to `~/git/drm-kmod/`

You can then override them with something like
`DRMKMODDIR=/home/ashafer/git/drm-kmod/ make`.

Ensure that both of these are populated with their corresponding projects
via the following:
```
git clone https://github.com/freebsd/freebsd-src/ 
# see below for details on which branch to use
git clone https://github.com/freebsd/drm-kmod --branch <branch_name>
```

In the case of `drm-kmod` you may wish to specify a branch. The branch chosen
must match what supports your FreeBSD version and your installation of drm-kmod
(if you installed it through pkg).

Ex:
* For `14.0-CURRENT` use `master`
* For `13.1-*` use `5.10-lts`

## Installing

```
$ cd nvidia
$ make && make install
$ kldload nvidia-drm
```

## Reporting issues

Please report issues with thorough descriptions of how to reproduce the
problem, preferably accompanied by a coredump summary or stack trace when
appropriate. This makes things significantly easier to debug.

# Known Issues

Individual bugs can be reported in the Github issues tab, but the following are
known issues that are currently not supported:

* Suspend/Resume on Wayland: This driver can actually do suspend/resume just
  fine, the issue is that the Nvidia FreeBSD driver currently does not have
  support for "Persistent Video Memory". This feature backs up video memory to
  a file on suspend, and reads it back on resume. Details can be found
  [here](https://download.nvidia.com/XFree86/Linux-x86_64/435.17/README/powermanagement.html)
* Panics on `kldunload`: This hasn't fully been root caused yet, but it seems
  to have something to do with the way `linuxkpi` tears things down. Since I
  don't believe this works with the intel/amd drivers supported in `drm-kmod`,
  I have no plans to fix this for now.

## Other Relevant Links

* [Porting nvidia-drm.ko to FreeBSD](https://badland.io/nvidia-drm.md) (2019-08-01)
* [Anatomy of the FreeBSD NVIDIA driver](https://badland.io/nvidia.md) (2019-08-01)
* [Announcing nvidia-drm port and Call for Testing](https://badland.io/announcing_nvidia_drm.md) (2022-11-13)
* [Configuring PRIME in 2023 (on FreeBSD)](https://badland.io/prime-configuration.md) (2023-04-13)

## How to update this port

Updating information can be found in [UPDATING.md](UPDATING.md)
