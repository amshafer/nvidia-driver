#
# Test whether certain compiler flags are supported,
# and add them to CFLAGS if so.
#
_cflag_test_cmd_prefix= if ${CC} -o /dev/null -c -x c /dev/null
_cflag_test_cmd_suffix= > /dev/null 2>&1; then echo "y"; fi

#
# -Werror=undef: treat undefined preprocessor identifiers as errors.
# Added in GCC 4.2.0.
#
_opt= -Werror=undef
WERROR_UNDEF_SUPPORTED!= \
    ${_cflag_test_cmd_prefix} \
    ${_opt} \
    ${_cflag_test_cmd_suffix}

.if ${WERROR_UNDEF_SUPPORTED} == "y"
CFLAGS+= ${_opt}
.endif
