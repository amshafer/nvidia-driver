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

Please note that this is currently in the testing stage. While the changes are
very stable and can be used to comfortably run a Wayland desktop, more testing
is needed before this starts to make its way into the ports tree. Please help
by giving it a go and reporting any issues you may find!


## Installing

```
$ cd nvidia
$ make && make install
$ kldload nvidia-drm
```

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
* https://badland.io/nvidia-drm.md
* https://badland.io/nvidia.md
