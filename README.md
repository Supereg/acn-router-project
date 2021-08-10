Setting up DPDK
===============

Compile DPDK
```
	cd dpdk
	meson build
	cd build
	ninja
	ninja install
	ldconfig
```


Load the `vfio-pci` driver :
```
	modprobe uio
	modprobe uio_pci_generic
```

Use the tool `dpdk-devbind.py` to bind the VirtIO NICs to the `uio_pci_generic` driver.
(Find out how to do this, the tool is self-explanatory.)
```
	usertools/dpdk-devbind.py --h
```

Setup hugetlbfs huge pages for DPDK
```
	mkdir /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge
```

Statically allocate 256 2MB huge pages
```
	echo 256 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
```

Compiling your App
==================

This example project comes with a CMakeFile and a simple wrapper that initializes DPDK for you.
Run the following steps to build the router app
```
	cmake .
	make
```

That's all!


DPDK Reference
==============

For this project, we use DPDK 20.11 (LTS).
The comprehensive DPDK documentation can ge found at:

* [HTML guides](https://doc.dpdk.org/guides-20.11/)
* [HTML API](https://doc.dpdk.org/api-20.11/)


Compiling gtest
===============

Installing/Compiling gtest is no longer necessary, VM contains compiled library.

Remark on ACN-VM
================

add recv_from_device() utility function

Apparently our virtual switch works different from last year and sets rx = tx queues with automatic load balancing
(even when not configured) so this is a simple work-around.

