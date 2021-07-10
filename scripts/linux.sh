#!/bin/sh

sysctl compat.linux.osname > /dev/null 2>&1; RESULT=$?
if [ ${RESULT} -eq 0 ]; then
	if [ -x /compat/linux/sbin/ldconfig ]; then
		/compat/linux/sbin/ldconfig > /dev/null 2>&1
	fi

	grep linux_enable /etc/rc.conf > /dev/null 2>&1; RESULT=$?
	if [ ${RESULT} -eq 0 ]; then
		# Present.
		sed -e s/linux_enable.*/linux_enable=\"YES\"/g -i.orig /etc/rc.conf
	else
		# Not present.
		echo 'linux_enable="YES"' >> /etc/rc.conf
	fi

	kldstat -v -n kernel | grep linux > /dev/null 2>&1 ; RESULT=$?
	if [ ${RESULT} -eq 0 ]; then
		# Linux ABI module built into kernel.
	else
		grep linux_load /boot/loader.conf > /dev/null 2>&1; RESULT=$?
		if [ ${RESULT} -eq 0 ]; then
			# Present.
			sed -e s/linux_load.*/linux_load=\"YES\"/g -i.orig /boot/loader.conf
		else
			# Not present.
			echo 'linux_load="YES"' >> /boot/loader.conf
		fi
	fi
fi
