#!/bin/sh

# NVIDIA Graphics Driver bug reporting shell script.  This shell
# script will generate a log file named "nvidia-bug-report.log.gz", which
# should be attached when emailing bug reports to NVIDIA.

PATH="/sbin:/usr/sbin:$PATH"

BASE_LOG_FILENAME="nvidia-bug-report.log"

# check if gzip is present
GZIP_CMD=`which gzip 2> /dev/null | head -n 1`
if [ $? -eq 0 -a "$GZIP_CMD" ]; then
    GZIP_CMD="gzip -c"
else
    GZIP_CMD="cat"
fi

DPY="$DISPLAY"
[ "$DPY" ] || DPY=":0"

set_filename() {
    if [ "$GZIP_CMD" = "gzip -c" ]; then
        LOG_FILENAME="$BASE_LOG_FILENAME.gz"
        OLD_LOG_FILENAME="$BASE_LOG_FILENAME.old.gz"
    else
        LOG_FILENAME=$BASE_LOG_FILENAME
        OLD_LOG_FILENAME="$BASE_LOG_FILENAME.old"
    fi
}

usage_bug_report_message() {
    echo "Please include the '$LOG_FILENAME' log file when reporting"
    echo "your bug to freebsd-gfx-bugs@nvidia.com."
    echo ""
    echo "By delivering '$LOG_FILENAME' to NVIDIA, you acknowledge"
    echo "and agree that personal information may inadvertently be included in"
    echo "the output.  Notwithstanding the foregoing, NVIDIA will use the"
    echo "output only for the purpose of investigating your reported issue."
}

usage() {
    echo ""
    echo "$(basename $0): NVIDIA FreeBSD Graphics Driver bug reporting shell script."
    echo ""
    usage_bug_report_message
    echo ""
    echo "$(basename $0) [ -h | --help ] [ -o | --output-file <file> ]"
    echo "    -h / --help"
    echo "        Print this help output and exit."
    echo "    --output-file <file>"
    echo "        Write output to <file>. If gzip is available, the output file"
    echo "        will be automatically compressed, and \".gz\" will be appended"
    echo "        to the filename. Default: write to nvidia-bug-report.log(.gz)."
    echo ""
}

NVIDIA_BUG_REPORT_CHANGE='$Change: 33421935 $'
NVIDIA_BUG_REPORT_VERSION=`echo "$NVIDIA_BUG_REPORT_CHANGE" | tr -c -d "[:digit:]"`

# Set the default filename so that it won't be empty in the usage message
set_filename

# Parse arguments: Optionally set output file or print help
BUG_REPORT_SAFE_MODE=0
SAVED_FLAGS=$@
while [ "$1" != "" ]; do
    case $1 in
        -o | --output-file )    if [ -z $2 ]; then
                                    usage
                                    exit 1
                                elif [ "$(echo "$2" | cut -c 1)" = "-" ]; then
                                    echo "Warning: Questionable filename"\
                                         "\"$2\": possible missing argument?"
                                fi
                                BASE_LOG_FILENAME="$2"
                                # override the default filename
                                set_filename
                                shift
                                ;;
        -h | --help )           usage
                                exit
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done

#
# echo_metadata() - echo metadata of specified file
#

echo_metadata() {
    printf "*** ls: "
    /bin/ls -l -D "%Y-%m-%d %H.%M.%S" "$1" 2> /dev/null

    if [ $? -ne 0 ]; then
        # Run dumb ls -l. We might not get one-second mtime granularity, but
        # that is probably okay.
        ls -l "$1" 2>&1
    fi
}

#
# append() - append the contents of the specified file to the log
#

append() {
    (
        echo "____________________________________________"
        echo ""

        if [ ! -f "$1" ]; then
            echo "*** $1 does not exist"
        elif [ ! -r "$1" ]; then
            echo "*** $1 is not readable"
        else
            echo "*** $1"
            echo_metadata "$1"
            cat  "$1"
        fi
        echo ""
    ) | $GZIP_CMD >> $LOG_FILENAME
}

#
# append_silent() - same as append(), but don't print anything
# if the file does not exist
#

append_silent() {
    (
        if [ -f "$1" -a -r "$1" ]; then
            echo "____________________________________________"
            echo ""
            echo "*** $1"
            echo_metadata "$1"
            cat  "$1"
            echo ""
        fi
    ) | $GZIP_CMD >> $LOG_FILENAME
}

#
# append_glob() - use the shell to expand a list of files, and invoke
# append() for each of them
#

append_glob() {
    for append_glob_iterator in `ls $1 2> /dev/null;`; do
        append "$append_glob_iterator"
    done
}

#
# append_file_or_dir_silent() - if $1 is a regular file, append it; otherwise,
# if $1 is a directory, append all files under it.  Don't print anything if the
# file does not exist.
#

append_file_or_dir_silent() {
    if [ -f "$1" ]; then
        append "$1"
    elif [ -d "$1" ]; then
        append_glob "$1/*"
    fi
}

#
# append_sysctl() - use sysctl to retrieve the value of interesting
# kernel or driver state variables.
#

append_sysctl() {
    (
        echo "____________________________________________"
        echo ""

        sysctl=`which sysctl 2> /dev/null | head -n 1`
        if [ $? -eq 0 -a "$sysctl" ]; then
            value=`$sysctl $1 2> /dev/null`
            if [ $? -eq 0 -a "$value" ]; then
                echo "$value"
            else
                echo "$1 does not exist"
            fi
        else
            echo "sysctl not found"
        fi
    ) | $GZIP_CMD >> $LOG_FILENAME
}


#
# Start of script
#


# check that we are root (potentially needed for accessing kernel log files)

if [ `id -u` -ne 0 ]; then
    echo "ERROR: Please run $(basename $0) as root."
    exit 1
fi


# move any old log file (zipped) out of the way

if [ -f $LOG_FILENAME ]; then
    mv $LOG_FILENAME $OLD_LOG_FILENAME
fi


# make sure what we can write to the log file

touch $LOG_FILENAME 2> /dev/null

if [ $? -ne 0 ]; then
    echo
    echo "ERROR: Working directory is not writable; please cd to a directory"
    echo "       where you have write permission so that the $LOG_FILENAME"
    echo "       file can be written."
    echo
    exit 1
fi


# print a start message to stdout

echo ""
echo "$(basename $0) will now collect information about your"
echo "system and create the file '$LOG_FILENAME' in the current"
echo "directory.  It may take several seconds to run.  In some"
echo "cases, it may hang trying to capture data generated dynamically"
echo "by the FreeBSD kernel and/or the NVIDIA kernel module.  While"
echo "the bug report log file will be incomplete if this happens, it"
echo "may still contain enough data to diagnose your problem." 
echo ""
usage_bug_report_message
echo ""
echo -n "Running $(basename $0)...";


# print prologue to the log file

(
    echo "____________________________________________"
    echo ""
    echo "Start of NVIDIA bug report log file.  Please send this"
    echo "report along with a description of your bug, to"
    echo "freebsd-gfx-bugs@nvidia.com."
    echo ""
    echo "nvidia-bug-report.sh Version: $NVIDIA_BUG_REPORT_VERSION"
    echo ""
    echo "Date: `date`"
    echo "uname: `uname -a`"
    echo ""
) | $GZIP_CMD >> $LOG_FILENAME


# append useful sysctl keys

append_sysctl "hw.nvidia.version"
append_sysctl "hw.nvidia.cards"
append_sysctl "hw.nvidia.agp"
append_sysctl "hw.nvidia.registry"

append_sysctl "vm.vmtotal"
append_sysctl "kern.version"
append_sysctl "kern.smp"

# append useful files

append "/etc/motd"


# append the X log; also, extract the config file named in the X log
# and append it; look for X log files with names of the form:
# /var/log/Xorg.{0,1,2,3,4,5,6,7}.{log,log.old}

xconfig_file_list=

for i in 0 1 2 3 4 5 6 7; do
    for log_suffix in log log.old; do
        log_filename="/var/log/Xorg.${i}.${log_suffix}"
        append_silent "${log_filename}"

        # look for the X configuration files/directories referenced by this X log
        if [ -f ${log_filename} -a -r ${log_filename} ]; then
            config_file=`grep "Using config file" ${log_filename} | cut -f 2 -d \"`
            config_dir=`grep "Using config directory" ${log_filename} | cut -f 2 -d \"`
            sys_config_dir=`grep "Using system config directory" ${log_filename} | cut -f 2 -d \"`
            for j in "$config_file" "$config_dir" "$sys_config_dir"; do
                if [ "$j" ]; then
                    # multiple of the logs we find above might reference the
                    # same X configuration file; keep a list of which X
                    # configuration files we find, and only append X
                    # configuration files we have not already appended
                    echo "${xconfig_file_list}" | grep ":${j}:" > /dev/null
                    if [ "$?" != "0" ]; then
                        xconfig_file_list="${xconfig_file_list}:${j}:"
                        if [ -d "$j" ]; then
                            append_glob "$j/*.conf"
                        else
                            append "$j"
                        fi
                    fi
                fi
            done
        fi
    done
done

# Append any config files found in home directories
cat /etc/passwd \
    | cut -d : -f 6 \
    | sort | uniq \
    | while read DIR; do
        append_file_or_dir_silent "$DIR/.nv/nvidia-application-profiles-rc"
        append_file_or_dir_silent "$DIR/.nv/nvidia-application-profiles-rc.backup"
        append_file_or_dir_silent "$DIR/.nv/nvidia-application-profiles-rc.d"
        append_file_or_dir_silent "$DIR/.nv/nvidia-application-profiles-rc.d.backup"
        append_silent "$DIR/.nv/nvidia-application-profile-globals-rc"
        append_silent "$DIR/.nv/nvidia-application-profile-globals-rc.backup"
        append_silent "$DIR/.nvidia-settings-rc"
    done

# Capture global app profile configs
append_file_or_dir_silent "/etc/nvidia/nvidia-application-profiles-rc"
append_file_or_dir_silent "/etc/nvidia/nvidia-application-profiles-rc.d"
append_file_or_dir_silent /usr/share/nvidia/nvidia-application-profiles-*-rc

# append vmstat info

(
    echo "____________________________________________"
    echo ""

    vmstat=`which vmstat 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$vmstat" ]; then
        echo "$vmstat"
        echo ""
        $vmstat 2> /dev/null
        echo ""
        echo "____________________________________________"
        echo ""
        echo "$vmstat -a -i"
        echo ""
        $vmstat -a -i 2> /dev/null
        echo ""
    else
        echo "Skipping vmstat output (vmstat not found)"
        echo ""
    fi
) | $GZIP_CMD >> $LOG_FILENAME

# append kldstat info

(
    echo "____________________________________________"
    echo ""

    kldstat=`which kldstat 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$kldstat" ]; then
        echo "$kldstat -v"
        echo ""
        $kldstat -v 2> /dev/null
        echo ""
    else
        echo "Skipping kldstat output (kldstat not found)"
        echo ""
    fi
) | $GZIP_CMD >> $LOG_FILENAME


# append ldd info

(
    echo "____________________________________________"
    echo ""

    glxinfo=`which glxinfo 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$glxinfo" ]; then
        echo "ldd $glxinfo"
        echo ""
        ldd $glxinfo 2> /dev/null
        echo ""
    else
        echo "Skipping ldd output (glxinfo not found)"
        echo ""
    fi
) | $GZIP_CMD >> $LOG_FILENAME

# pciconf information

(
    echo "____________________________________________"
    echo ""

    pciconf=`which pciconf 2> /dev/null | head -n 1`

    if [ $? -eq 0 -a -x "$pciconf" ]; then
        echo "$pciconf -l -v"
        echo ""
        $pciconf -l -v 2> /dev/null
        echo ""
    else
        echo "Skipping pciconf output (pciconf not found)"
        echo ""
    fi
) | $GZIP_CMD >> $LOG_FILENAME

# get any relevant kernel messages

(
    echo "____________________________________________"
    echo ""
    echo "Scanning kernel log files for NVIDIA kernel messages:"
    echo ""

    for i in /var/log/messages /var/log/kernel.log ; do
        if [ -f $i -a -r $i ]; then
            echo "  $i:"
            ( cat $i | grep -e NVRM -e nvidia- ) 2> /dev/null
        else
            echo "$i is not readable"
        fi
    done
) | $GZIP_CMD >> $LOG_FILENAME

# append dmesg output

(
    echo ""
    echo "____________________________________________"
    echo ""
    echo "dmesg:"
    echo ""
    dmesg 2> /dev/null
) | $GZIP_CMD >> $LOG_FILENAME

# print the gcc & g++ version info

(
    which gcc >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "____________________________________________"
        echo ""
        gcc -v 2>&1
    fi

    which g++ >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "____________________________________________"
        echo ""
        g++ -v 2>&1
    fi
) | $GZIP_CMD >> $LOG_FILENAME

# In case of failure, if xset returns with delay, we print the
# message from check "$?" & if it returns error immediately before kill,
# we directly write the error to the log file.

(
    echo "____________________________________________"
    echo ""
    echo "xset -q:"
    echo ""

    xset -q 2>&1 & sleep 1 ; kill -9 $! > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        # The xset process is still there.
        echo "xset could not connect to an X server"
    fi
) | $GZIP_CMD >> $LOG_FILENAME

# In case of failure, if nvidia-settings returns with delay, we print the
# message from check "$?" & if it returns error immediately before kill,
# we directly write the error to the log file.

(
    echo "____________________________________________"
    echo ""
    echo "nvidia-settings -q all:"
    echo ""

    DISPLAY= nvidia-settings -c "$DPY" -q all 2>&1 & sleep 1 ; kill -9 $! > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        # The nvidia-settings process is still there.
        echo "nvidia-settings could not connect to an X server"
    fi
) | $GZIP_CMD >> $LOG_FILENAME

# In case of failure, if xrandr returns with delay, we print the
# message from check "$?" & if it returns error immediately before kill,
# we directly write the error to the log file.

(
    if [ -x "`which xrandr 2>/dev/null`" ] ; then
         echo "____________________________________________"
         echo ""
         echo "xrandr --verbose:"
         echo ""

         xrandr -display $DPY --verbose 2>&1 & sleep 1 ; kill -9 $! > /dev/null 2>&1
         if [ $? -eq 0 ]; then
             # The xrandr process is still there.
             echo "xrandr could not connect to an X server"
         fi
    else
        echo "Skipping xrandr output (xrandr not found)"
    fi
) | $GZIP_CMD >> $LOG_FILENAME

(
    echo "____________________________________________"

    # print epilogue to log file

    echo ""
    echo "End of NVIDIA bug report log file."
) | $GZIP_CMD >> $LOG_FILENAME


# Done

echo " complete."
echo ""
echo "The file $LOG_FILENAME has been created; please send this"
echo "report, along with a description of your bug, to"
echo "freebsd-gfx-bugs@nvidia.com."
echo ""
