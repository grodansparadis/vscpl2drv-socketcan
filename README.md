# vscpl2drv-socketcan

Socketcan level II driver

- **Available for:** Linux
- **Driver Linux**: vscpl2_socketcandrv.so

This driver interface SocketCAN, the official CAN API of the Linux kernel, has been included in the kernel for a long time now. Meanwhile, the official Linux repository has device drivers for all major CAN chipsets used in various architectures and bus types. SocketCAN offers the user a multiuser capable as well as hardware independent socket-based API for CAN based communication and configuration. Socketcan nowadays give access to the major CAN adapters that is available on the market. Note that as CAN only can handle Level I events only events up to class < 1024 can be sent to this device. Other events will be filtered out.



The configuration string have the following format

> interface  (For example can0/can1/can2...)

##### Interface

The parameter interface is the socketcan interface to use. Typically this is can0, can0, can1... Defaults is vcan0 the first virtual interface. If the variable prefix_interface is available it will be used instead of the configuration value.

 | Variable name | Type   | Description |
 | ------------- | ----   | -----------   |
 | _interface    | string | The socketcan interface to use. Typically this is “can0, can0, can1...” Defaults is vcan0 the first virtual interface. |
 | _filter       | string | Standard VSCP filter in string form. 1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00 as priority,class,type,GUID Used to filter what events that is received from the socketcan interface. If not give all events are received. |
 | _mask         | string | Standard VSCP mask in string form. 1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00 as priority,class,type,GUID Used to filter what events that is received from the socketcan interface. If not give all events are received.   |

The full variable name is built from the name you give the driver (prefix before _variablename) in vscpd.conf. So in the examples below the driver have the name **socketcan1** and the full variable name for the **_interface** will thus be

> socketcan1_interface

If you have another diver and name it  **socketcan2** it will therefore instead request variable **socketcan2_interface**

If your driver name contains spaces, for example “name of driver” it will get a prefix that is “name_of_driver”. Leading and trailing spaces will be removed.

##### vscpd.conf example

```xml
<driver enable="true" >
    <name>socketcan1</name>
    <path>/usr/local/lib/vscpl2_socketcandrv.so</path>
    <config>can0</config>
    <guid>00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00</guid>
</driver>
```
## Build the driver

To build the driver you follow the same procedure as with all autoconf based builds

```bash
./configure
make
make install
```

The driver will be installed into */usr/local/lib*. Note that the debian package will install to */usr/lib*.

## Build a debian package
Use the supplied script *build_debian_package.sh*. The script will automatically build a debian package. You find the package files under */tmp/_BUILD_*

---


## Notes

*  Some notes about socketcan is [here](http://www.akehedman.se/wiki/doku.php/socketcan).


The VSCP project homepage is here <https://www.vscp.org>.

The [manual](https://grodansparadis.gitbooks.io/the-vscp-daemon) for vscpd contains full documentation. Other documentation can be found here <https://grodansparadis.gitbooks.io>.

The vscpd source code may be downloaded from <https://github.com/grodansparadis/vscp>. Source code for other system components of VSCP & Friends are here <https://github.com/grodansparadis>

## Copyright
Copyright (C) 2000-2020 Ake Hedman, Grodans Paradis AB - MIT license.
