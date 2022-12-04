# Documentation on how to update this port

nvidia-drm is a set of patches applied to the base Nvidia driver. This
documents how we apply said patches, and what the process looks like.

In summary, the steps are:
* Update the patches
* Populate the baseline branch with a set of driver files
* Apply the patches
* Test the build

#### NOTE

These steps are usually performed by the owner of this repository. If you plan
on using this to update a driver please be aware that you may be duplicating
work. If the driver version you need has not been populated feel free to reach
out and request it.

### Baseline 

The `baseline` branch is the starting point. All driver versions will branch
off of this, meaning you can walk back in the git history and see what patches
were applied to a particular branch. The baseline is important because it holds
script versions and the git patchces to be applied to the driver source tree
once it is populated.

### Populating a driver

Driver population is automated by the `populate_driver.sh` script. This script
accepts a driver version number, and will go download the corresponding FreeBSD
and Linux drivers. It will then unpack the drivers to their proper locations in
the `nvidia/` subdir. Both drivers are needed since the `nvidia-drm` files will
come from the Linux driver as they are not currently shipped in the FreeBSD
tarball.

```
# Checkout the 525.53 beta driver, the first with nvidia-drm support
./populate_driver.sh 525.53
```

### Updating Patches

Updating patches is done on a driver, and the diff will be placed in the
`patches/` directory. There are two different sets of patches stored:
* `patches/compat` - These are patches that update the FreeBSD compatibility.
  These are patches that will be merged into the base driver shipped by Nvidia,
  but aren't present yet. We have to apply them ourselves just like the FreeBSD
  ports tree has to.
* `patches/drm/` - These are the patches applied to the nvidia-drm sources
  taken from the Linux driver. These patches implement FreeBSD support for
  nvidia-drm.ko, and are where the FreeBSD vs Linux workarounds live.

This separation makes it easier to keep track of patches, since the `comapt`
patches will vary depending on the driver version and aren't directly related
to the `nvidia-drm` bits.

### Applying patches

Applying patches is not completely automated. This is because there will be a
certain amount of mismatch with the patches depending on the driver version it
is being applied to (due to normal code churn). The workflow uses `git am` with
the normal patch utility to partially apply diffs:

```
./populate_driver.sh 525.53

# Apply the compat patches
git am patches/compat/*

# Now apply the DRM patches, order does matter and this must be second
git am patches/drm/*

# If there is a conflict do
patch -p1 < patches/.../<patch_name>

# If git am cannot merge the above patches it will bail partway through and you
# must fix things yourself. This is normally fairly trivial conflict resolution.
#
# Open all the rejected chunks
vim **/*.rej

# ... resolve conflicts manually ...

# Now add the affected files and continue with the patch series.
#
# NOTE: There are a couple files (nvidia/src/nvidia-drm/nvidia-drm-freebsd-lkpi.c)
# which are new files added by the patches. They might show up in the untracked
# files section of git, so make sure to add them too!

git add -u 
# If needed: git add nvidia/src/nvidia-drm/nvidia-drm-freebsd-lkpi.c
git am --continue

... repeat above until all patches applied ...

```

*There is one final step*: Manually update the version string in
nvidia/src/nvidia-drm/Makefile. This is needed so that `nvidia.ko` and
`nvidia-drm.ko` advertise the same version (which they are) and see each other
as compatible. 

At this point you'll have a new branch who you should have named after the
version of the driver it hosts.

### Test the build

See the [README](../README.md) for details on how to build the driver.
Automated build CI will be present if you enable Cirrus CI and push your new
branch.

Keep in mind that you may have to test the driver against multiple FreeBSD and
drm-kmod port versions, as the drm-kmod interface may change a fair amount and
you must ensure the compat script (`nvidia/src/nvidia-drm/conftest.sh`) can
handle it.
