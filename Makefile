# This Makefile plumbs down to the nvidia/ directory, which
# is needed for the ports tree as it expects a Makefile in
# the root directory

SUBDIR=	nvidia

.include <bsd.subdir.mk>
