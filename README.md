# Hijacking DJI Phantom 2 Vision and P2V+ (eventually)
     -- noah@hack.se, July 2014

This is a code dump of an ongoing research project with the goal of hijacking  [Phantom 2 Vision](http://www.dji.com/product/phantom-2-vision) and [Phantom 2 Vision+](http://www.dji.com/product/phantom-2-vision-plus) quadcopters.

These products are based on DJI's Phantom 2 platform but the P2V comes with a anti-vibration camera platform with single-axis stabilization whereas the P2V+ comes with a camera stabilized on a 3-axis gimbal.

The quadcopter is controlled using a [5.8GHz remote](http://fccid.net/number.php?fcc=SS3-201309581&id=923239). Telemetry and live video preview is available through the DJI Vision app ([iOS](https://itunes.apple.com/en/app/dji-vision/id669439159)/[Android](https://play.google.com/store/apps/details?id=com.dji.vision)), which connects to the Phantom through a WiFi-network provided by a device called the Range Extender.

The Range Extender is essentially a small Linux system based on OpenWRT which provides a WiFi-network used by the Phantom and the DJI Vision App.  It's reachable over SSH at 192.168.1.2 (root / 19881209).

The WiFi-network has no security by default and neither the Phantom nor the DJI Vision app supports password protecting it.  Additionally, it is required that the network name is prefixed with "Phantom_" in order for the Phantom to find and associate with it.

In addition to the Range Extender, the Phantom itself sports two ARM-based Linux systems (probably on the camera module itself).

The first Linux system seems to a be a general purpose system which is hooked up to the flight controller via a serial port. The serial port communication is exposed over TCP port 2001 ([ser2net](http://ser2net.sourceforge.net/)), which is what the DJI Vision app uses to talk to the Phantom.The system also provides access to the SD card via a webserver in order to allow images and recordings to be downloaded through the DJI Vision app.
It can be accessed via SSH at 192.168.1.1 (root / 19881209).

The second system lives at 192.168.1.10 (root / 123456) and seems to be responsible for video recording and encoding. During flight it provides live video on UDP port 9000, over a protocol that seems to ressemble [UDP-based Data Transfer](http://udt.sourceforge.net/) (though it's not following the spec..)

(For more details on the Linux systems, see [this thread](http://www.phantompilots.com/viewtopic.php?p=185401#p185401))

During flight the DJI Vision app is in constant communication with the flight controller over the ser2net protocol. Should this communication break for a longer period, the Phantom will return to its recorded home point and land. The communication happens in plaintext and so far I've managed to decode the most interesting packet types, including battery status, GPS coordinates, altitude, heading, ...

One of the things that are new with the DJI Phantom 2 Vision and the P2V+ is the ability to program routes with up to 16 waypoints.  Support for this is also available on the original Phantom 2 with additional hardware and more recent (March, 2014) versions of the firmware.

Conveniently this programming, and the command to execute the route, is performed over WiFi via the ser2net protocol. The communication is encrypted, however, using a modified (*q = 1 + 52/n*) version of the Corrected Block TEA ([XXTEA](https://en.wikipedia.org/wiki/XXTEA)) cipher.

Currently I'm stuck with computing the checksum for those encrypted packets. So far it doesn't seem to be something XOR-based, like what's used for the non-encrypted communication. I'm leaning towards the possibility it might be a CRC-16 variant, though I haven't found the time to try it out yet. There are also more work remaining in order to completely reverse engineer how waypoints are defined and finally executed.

The `dji-phantom.c` in the repo is the tool I'm using to talk to the Phantom and to debug packet data with.

## Grabbing packets from DJI Vision app communication

Grab libpcap and tcpdump packages from the OpenWRT [ar71xx repo](http://downloads.openwrt.org/snapshots/trunk/ar71xx/packages/base/).  Install these packages onto the WiFi Range Extender:

    # root password is: 19881209
    $ scp tcpdump-mini_4.5.1-4_ar71xx.ipk libpcap_1.5.3-1_ar71xx.ipk root@192.168.1.2:/tmp
    $ ssh root@192.168.1.2
    ...
    root@Phantom:~# cd /tmp
    root@Phantom:/tmp# opkg install libpcap_1.5.3-1_ar71xx.ipk tcpdump-mini_4.5.1-4_ar71xx.ipk
    Installing libpcap (1.5.3-1) to root...
    Installing tcpdump-mini (4.5.1-4) to root...
    Configuring libpcap.
    Configuring tcpdump-mini.
    root@Phantom:/tmp# rm *.ipk
    root@Phantom:/tmp# 
 
Start recording some traffic after you've associated with the Range Extender:

    # root password is: 19881209
    $ ssh root@192.168.1.2 tcpdump -ns 0 -i br-lan -w - port 2001  > dji-dump-123.pcap

Open up the DJI Vision app and do interesting stuff.

Hit Ctrl-C on the tcpdump session after closing the DJI Vision app. Open the resulting .pcap-file in Wireshark. Choose Analyze > Follow TCP Stream.  Choose to display "hex dump".  Choose Save and save to a text file, e.g. `dji-dump-123.hex`.

Optionally, parse the output with the (buggy) php script in the repo:

    $ php dji-parse-wireshark-hexdump.php dji-dump-123.hex > dji-dump-123.txt 2>&1

This will result in a file containing data such as:

    CLIENT seq:000000, len   9, flags 0x08, cmd 0x04, data: '01'
    SERVER seq:000000, len   9, flags 0x48, cmd 0x04, data: '00'
    CLIENT seq:000001, len  15, flags 0x08, cmd 0x20, data: '14200726074259'
    ...
    SERVER seq:000019, len  24, flags 0x4a, cmd 0x53, data: '0050145014f6126f3076fc615d180900'


From it you can extract the datapart and prepend the command number and have `dji-phantom` parse it using the `-x` switch:

    $ make dji-phantom && ./dji-phantom -x 2014200726074259
    cc     dji-phantom.c   -o dji-phantom
    ** Rcv from port 0x00, seq     0, cmd 0x20, error 0, payload len  7
    [0x20]: Camera time initialized to 2014-07-26 07:42:59
    
    $ ./dji-phantom -x 530050145014f6126f3076fc615d180900
    ** Rcv from port 0x00, seq     0, cmd 0x53, error 0, payload len  16
    [0x53]: Seq     0, battery capacity design/full/now 5200/5200/1332mAh, status <11201mV,  -983mA>, discharges   9, temp 39C, battery life/charge 97%/25%

For more information, please refer to `dji-phantom.c`.

## Prior research:

- [Hacking the Phantom](http://www2.cs.uidaho.edu/~oman/CS536/TeamReaperDroneSummaryAbridged.pptx) (the original v1 model)
- [DJI NAZA GPS communication protocol - NazaDecoder Arduino library](http://www.rcgroups.com/forums/showthread.php?t=1995704)
- [DJI NAZA CAN bus communication protocol - NazaCanDecoder Arduino library](http://www.rcgroups.com/forums/showthread.php?t=2071772)

