#!/bin/bash
eth_info=$(realpath eth-info)
source dpdk-config.sh
sudo modprobe uio
sudo rmmod igb_uio
sudo insmod ./build/kmod/igb_uio.ko
set_non_numa_pages 512
echo "------------------------------------------------------------------------------"
while read line
do
    arr=($line)
    if [ ${arr[2]} == 'YES' ]; then
        if ifconfig | grep ${arr[1]}; then
            sudo ifconfig ${arr[1]} down
        fi
        bind_devices_to_igb_uio ${arr[0]}
    else
        ifconfig | grep ${arr[1]} > /dev/null
        if [ $? == 1 ]; then
            unbind_devices ${arr[0]} ${arr[3]}
        fi
    fi
done < $eth_info
echo "------------------------------------------------------------------------------"
echo "Config OK."
show_devices
