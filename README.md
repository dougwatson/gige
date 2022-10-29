# README #

This repo is for archive and knowledge sharing purposes. There is no support because I don't use these cameras anymore- but pull requests and forks are welcome. It's for developers who want to explore GIGE camera control with a 100% pure GO solution (no drivers needed). I developed this for aca2440 cameras, but has also been tested with some Lucid cameras and should work with small changes for other GIGE camera manufacturers as well.


### About ###

Controlling GIGE Vision cameras like the Basler line of ethernet cameras (i.e. aca2440-20gc).
This is a pure Go application that enables reading and writing to memory registers 
in the camera over a UDP connection.

### Quick start ###

Dependencies - no drivers are needed just GO!
It has been tested on Linux and MacOS platforms.

------------------------------------------------------------

Find the executable, connect your camera and run it - 

#### Find your go path and cd to it:
```
go env| grep GOPATH
```
(cd to it, then)

```
cd bin
```

#### You should see the program named 'gige' compiled in there:

Now find your device (-d) by running ifconfig and look for the ethernet device 
connected to you camera POE switch

The remote address (-raddr) is the ip address of the camera you want to control.
If you don't know the IP addres, then you can use the broadcast address 255.255.255.255.

The top section returned, is what we sent, the bottom (packets received) is what we 
got back from the camera.


```$ ./gige -d en9 -raddr 255.255.255.255```

![picture](img/gige-camera-search.png)


```$ ./gige -d en9 -raddr 255.255.255.255 -readAll```

![picture](img/gige-camera-readall.png)

## Troubleshooting ##

If you get the message "Unable to find interface", then either your camera is not
connected through the POE switch to your computer, or you provided the wrong interface (-d).

### To find the ethernet interface you just plugged your camera switch into ###

Run this right after you plug in the cable to your linux or macos computer to see it show up.
You are looking for the port number (in this case 9).

```>sudo dmesg```

AppleThunderboltNHIType3::prePCIWake - took 0 us
AppleThunderboltNHIType3::prePCIWake - took 0 us
Thunderbolt 0 PCI - LS=0xd043 LC=0x0040 SS=0x0048 SC=0x0000 PMCSR=0x0008 RT=0x0000 NLRT=0xffffffff LWRT=0xffffffff PRRT=0xffffffff TRT=0x0000 TNLRT=0x0000 TLWRT=0x0000 TPRRT=0x0000 TLUP=0x0001
Thunderbolt 0 PCI - LS=0xd043 LC=0x0040 SS=0x0048 SC=0x0000 PMCSR=0x0008 RT=0x0000 NLRT=0xffffffff LWRT=0xffffffff PRRT=0xffffffff TRT=0x0000 TNLRT=0x0000 TLWRT=0x0000 TPRRT=0x0000 TLUP=0x0001
AppleThunderboltGenericHAL::earlyWake - complete - took 0 milliseconds
AppleThunderboltGenericHAL::earlyWake - complete - took 0 milliseconds
IOThunderboltSwitch<0>(0x0)::listenerCallback - Thunderbolt HPD packet for route = 0x0 port = 9 unplug = 0
IOThunderboltSwitch<0>(0x0)::listenerCallback - Thunderbolt HPD packet for route = 0x0 port = 10 unplug = 0
IOHIDLibUserClient:0x1000052e4 message: 0xe0000230 from: 0x1000052b0

Then you can verify with ifconfig. You should now see a new entry.

```> ifconfig```

en9: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 9000
	options=50b<RXCSUM,TXCSUM,VLAN_HWTAGGING,AV,CHANNEL_IO>
	.....


