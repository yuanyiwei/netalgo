#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

#
# Run with "source /path/to/dpdk-setup.sh"
#

#
# Change to DPDK directory ( <this-script's-dir>/.. ), and export it as RTE_SDK
#

echo "------------------------------------------------------------------------------"
echo " RTE_SDK exported as $RTE_SDK"
echo "------------------------------------------------------------------------------"

cd $RTE_SDK

HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`

#
# Application EAL parameters for setting memory options (amount/channels/ranks).
#
EAL_PARAMS='-n 4'

#
# Sets QUIT variable so script will finish.
#
quit()
{
	QUIT=$1
}

# Shortcut for quit.
q()
{
	quit
}

#
# Sets up environmental variables for ICC.
#
setup_icc()
{
	DEFAULT_PATH=/opt/intel/bin/iccvars.sh
	param=$1
	shpath=`which iccvars.sh 2> /dev/null`
	if [ $? -eq 0 ] ; then
		echo "Loading iccvars.sh from $shpath for $param"
		source $shpath $param
	elif [ -f $DEFAULT_PATH ] ; then
		echo "Loading iccvars.sh from $DEFAULT_PATH for $param"
		source $DEFAULT_PATH $param
	else
		echo "## ERROR: cannot find 'iccvars.sh' script to set up ICC."
		echo "##     To fix, please add the directory that contains"
		echo "##     iccvars.sh  to your 'PATH' environment variable."
		quit
	fi
}

#
# Sets RTE_TARGET and does a "make install".
#
setup_target()
{
	option=$1
	export RTE_TARGET=${TARGETS[option]}

	compiler=${RTE_TARGET##*-}
	if [ "$compiler" == "icc" ] ; then
		platform=${RTE_TARGET%%-*}
		if [ "$platform" == "x86_64" ] ; then
			setup_icc intel64
		else
			setup_icc ia32
		fi
	fi
	if [ "$QUIT" == "0" ] ; then
		make install T=${RTE_TARGET}
	fi
	echo "------------------------------------------------------------------------------"
	echo " RTE_TARGET exported as $RTE_TARGET"
	echo "------------------------------------------------------------------------------"
}

#
# Creates hugepage filesystem.
#
create_mnt_huge()
{
	echo "Creating /mnt/huge and mounting as hugetlbfs"
	sudo mkdir -p /mnt/huge

	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -ne 0 ] ; then
		sudo mount -t hugetlbfs nodev /mnt/huge
	fi
}

#
# Removes hugepage filesystem.
#
remove_mnt_huge()
{
	echo "Unmounting /mnt/huge and removing directory"
	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -eq 0 ] ; then
		sudo umount /mnt/huge
	fi

	if [ -d /mnt/huge ] ; then
		sudo rm -R /mnt/huge
	fi
}

#
# Unloads igb_uio.ko.
#
remove_igb_uio_module()
{
	echo "Unloading any existing DPDK UIO module"
	/sbin/lsmod | grep -s igb_uio > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod igb_uio
	fi
}

#
# Loads new igb_uio.ko (and uio module if needed).
#
load_igb_uio_module()
{
	if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko ];then
		echo "## ERROR: Target does not have the DPDK UIO Kernel Module."
		echo "       To fix, please try to rebuild target."
		return
	fi

	remove_igb_uio_module

	/sbin/lsmod | grep -s uio > /dev/null
	if [ $? -ne 0 ] ; then
		modinfo uio > /dev/null
		if [ $? -eq 0 ]; then
			echo "Loading uio module"
			sudo /sbin/modprobe uio
		fi
	fi

	# UIO may be compiled into kernel, so it may not be an error if it can't
	# be loaded.

	echo "Loading DPDK UIO module"
	sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko
	if [ $? -ne 0 ] ; then
		echo "## ERROR: Could not load kmod/igb_uio.ko."
		quit
	fi
}

#
# Unloads VFIO modules.
#
remove_vfio_module()
{
	echo "Unloading any existing VFIO module"
	/sbin/lsmod | grep -s vfio > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod vfio-pci
		sudo /sbin/rmmod vfio_iommu_type1
		sudo /sbin/rmmod vfio
	fi
}

#
# Loads new vfio-pci (and vfio module if needed).
#
load_vfio_module()
{
	remove_vfio_module

	VFIO_PATH="kernel/drivers/vfio/pci/vfio-pci.ko"

	echo "Loading VFIO module"
	/sbin/lsmod | grep -s vfio_pci > /dev/null
	if [ $? -ne 0 ] ; then
		if [ -f /lib/modules/$(uname -r)/$VFIO_PATH ] ; then
			sudo /sbin/modprobe vfio-pci
		fi
	fi

	# make sure regular users can read /dev/vfio
	echo "chmod /dev/vfio"
	sudo chmod a+x /dev/vfio
	if [ $? -ne 0 ] ; then
		echo "FAIL"
		quit
	fi
	echo "OK"

	# check if /dev/vfio/vfio exists - that way we
	# know we either loaded the module, or it was
	# compiled into the kernel
	if [ ! -e /dev/vfio/vfio ] ; then
		echo "## ERROR: VFIO not found!"
	fi
}

#
# Unloads the rte_kni.ko module.
#
remove_kni_module()
{
	echo "Unloading any existing DPDK KNI module"
	/sbin/lsmod | grep -s rte_kni > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod rte_kni
	fi
}

#
# Loads the rte_kni.ko module.
#
load_kni_module()
{
    # Check that the KNI module is already built.
	if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko ];then
		echo "## ERROR: Target does not have the DPDK KNI Module."
		echo "       To fix, please try to rebuild target."
		return
	fi

    # Unload existing version if present.
	remove_kni_module

    # Now try load the KNI module.
	echo "Loading DPDK KNI module"
	sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko
	if [ $? -ne 0 ] ; then
		echo "## ERROR: Could not load kmod/rte_kni.ko."
		quit
	fi
}

#
# Sets appropriate permissions on /dev/vfio/* files
#
set_vfio_permissions()
{
	# make sure regular users can read /dev/vfio
	echo "chmod /dev/vfio"
	sudo chmod a+x /dev/vfio
	if [ $? -ne 0 ] ; then
		echo "FAIL"
		quit
	fi
	echo "OK"

	# make sure regular user can access everything inside /dev/vfio
	echo "chmod /dev/vfio/*"
	sudo chmod 0666 /dev/vfio/*
	if [ $? -ne 0 ] ; then
		echo "FAIL"
		quit
	fi
	echo "OK"

	# since permissions are only to be set when running as
	# regular user, we only check ulimit here
	#
	# warn if regular user is only allowed
	# to memlock <64M of memory
	MEMLOCK_AMNT=`ulimit -l`

	if [ "$MEMLOCK_AMNT" != "unlimited" ] ; then
		MEMLOCK_MB=`expr $MEMLOCK_AMNT / 1024`
		echo ""
		echo "Current user memlock limit: ${MEMLOCK_MB} MB"
		echo ""
		echo "This is the maximum amount of memory you will be"
		echo "able to use with DPDK and VFIO if run as current user."
		echo -n "To change this, please adjust limits.conf memlock "
		echo "limit for current user."

		if [ $MEMLOCK_AMNT -lt 65536 ] ; then
			echo ""
			echo "## WARNING: memlock limit is less than 64MB"
			echo -n "## DPDK with VFIO may not be able to initialize "
			echo "if run as current user."
		fi
	fi
}

#
# Removes all reserved hugepages.
#
clear_huge_pages()
{
	echo > .echo_tmp
	for d in /sys/devices/system/node/node? ; do
		echo "echo 0 > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp
	done
	echo "Removing currently reserved hugepages."
	sudo sh .echo_tmp
	rm -f .echo_tmp

	remove_mnt_huge
}

#
# Creates hugepages.
#
set_non_numa_pages()
{
	clear_huge_pages

	#echo ""
	#echo "  Input the number of ${HUGEPGSZ} hugepages"
	#echo "  Example: to have 128MB of hugepages available in a 2MB huge page system,"
	#echo "  enter '64' to reserve 64 * 2MB pages"
	if [[ -n "$1" ]]; then
        #echo "$1"
        Pages=$1
    else
        echo -n "Number of pages: "
		read Pages
    fi

	echo "echo $Pages > /sys/kernel/mm/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" > .echo_tmp

	echo "Reserving hugepages: $Pages * 2MB."
	sudo sh .echo_tmp
	rm -f .echo_tmp

	create_mnt_huge
}

#
# Creates hugepages on specific NUMA nodes.
#
set_numa_pages()
{
	clear_huge_pages

	#echo ""
	#echo "  Input the number of ${HUGEPGSZ} hugepages for each node"
	#echo "  Example: to have 128MB of hugepages available per node in a 2MB huge page system,"
	#echo "  enter '64' to reserve 64 * 2MB pages on each node"

	echo > .echo_tmp
	for d in /sys/devices/system/node/node? ; do
		node=$(basename $d)
        if [[ -n "$1" ]]; then
            #echo "$1"
            Pages=$1
        else
            echo -n "Number of pages for $node: "
		    read Pages
        fi
		echo "echo $Pages > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp
	done
	echo "Reserving hugepages: $Pages * 2MB."
	sudo sh .echo_tmp
	rm -f .echo_tmp

	create_mnt_huge
}

#
# Run unit test application.
#
run_test_app()
{
	echo ""
	echo "  Enter hex bitmask of cores to execute test app on"
	echo "  Example: to execute app on cores 0 to 7, enter 0xff"
	echo -n "bitmask: "
	read Bitmask
	echo "Launching app"
	sudo ${RTE_TARGET}/app/test -c $Bitmask $EAL_PARAMS
}

#
# Run unit testpmd application.
#
run_testpmd_app()
{
	echo ""
	echo "  Enter hex bitmask of cores to execute testpmd app on"
	echo "  Example: to execute app on cores 0 to 7, enter 0xff"
	echo -n "bitmask: "
	read Bitmask
	echo "Launching app"
	sudo ${RTE_TARGET}/app/testpmd -c $Bitmask $EAL_PARAMS -- -i
}

#
# Print hugepage information.
#
grep_meminfo()
{
	grep -i huge /proc/meminfo
}

#
# Calls dpdk-devbind.py --status to show the devices and what they
# are all bound to, in terms of drivers.
#
show_devices()
{
	if [ -d /sys/module/vfio_pci -o -d /sys/module/igb_uio ]; then
		${RTE_SDK}/usertools/dpdk-devbind.py --status
	else
		echo "# Please load the 'igb_uio' or 'vfio-pci' kernel module before "
		echo "# querying or adjusting device bindings"
	fi
}

#
# Uses dpdk-devbind.py to move devices to work with vfio-pci
#
bind_devices_to_vfio()
{
	if [ -d /sys/module/vfio_pci ]; then
		${RTE_SDK}/usertools/dpdk-devbind.py --status
		echo ""
		echo -n "Enter PCI address of device to bind to VFIO driver: "
		read PCI_PATH
		sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b vfio-pci $PCI_PATH &&
			echo "OK"
	else
		echo "# Please load the 'vfio-pci' kernel module before querying or "
		echo "# adjusting device bindings"
	fi
}

#
# Uses dpdk-devbind.py to move devices to work with igb_uio
#
bind_devices_to_igb_uio()
{
	if [ -d /sys/module/igb_uio ]; then
		#${RTE_SDK}/usertools/dpdk-devbind.py --status
		#echo ""
        if [[ -n "$1" ]]; then
            #echo "$1"
            PCI_PATH=$1
        else
            echo -n "Enter PCI address of device to bind to IGB UIO driver: "
		    read PCI_PATH
        fi
		sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b igb_uio $PCI_PATH
        echo "Bind $PCI_PATH to igb_uio: OK."
	else
		echo "# Please load the 'igb_uio' kernel module before querying or "
		echo "# adjusting device bindings"
	fi
}

#
# Uses dpdk-devbind.py to move devices to work with kernel drivers again
#
unbind_devices()
{
	#${RTE_SDK}/usertools/dpdk-devbind.py --status
	#echo ""
    if [[ -n "$1" ]]; then
        #echo "$1"
        PCI_PATH=$1
    else
        echo -n "Enter PCI address of device to unbind: "
		read PCI_PATH
    fi
    if [[ -n "$2" ]]; then
        #echo "$2"
        DRV=$2
    else
        echo -n "Enter name of kernel driver to bind the device to: "
		read DRV
    fi
	sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b $DRV $PCI_PATH &&
    echo "Unbind $PCI_PATH, use driver $DRV: OK."
}
