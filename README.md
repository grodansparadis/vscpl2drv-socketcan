# vscpl2drv-socketcan

Socketcan level II driver

- **Available for:** Linux
- **Driver Linux**: libvscpl2_socketcandrv.so
- _Socketcan is not available on Windows_

This driver interface SocketCAN, the official CAN API of the Linux kernel, has been included in the kernel for a long time now. Meanwhile, the official Linux repository has device drivers for all major CAN chipsets used in various architectures and bus types. SocketCAN offers the user a multiuser capable as well as hardware independent socket-based API for CAN based communication and configuration. Socketcan nowadays give access to the major CAN adapters that is available on the market. Note that as CAN only can handle Level I events only events up to class < 1024 can be sent to this device. Other events will be filtered out.

Supports CAN FD.

## Install the driver
You can find binary installation files [here](https://github.com/grodansparadis/vscpl2drv-socketcan/releases)

You install the driver using the debian package with

> sudo apt install ./vscpl2drv-socketcan_15.0.0.deb

the driver will be installed to the folder _/var/lib/vscp/drivers/level2/_. 

After installing the driver you need to add configuration information for it to the vscpd.conf file (_/etc/vscp/vscpd.json_). Se the *configuration* section below.

You also need to set up the configuration file for the driver. If you don't need to dynamically edit the content of this file a good and safe location for it is in the */etc/vscp/* folder alongside the VSCP daemon configuration file.

If you need to do dynamic configuration (**write** enabled) we recommend that you create the file in the _/var/lib/vscp/_ folder or any location you find to be convenient.

A sample configuration file is available in _/usr/share/vscpl2drv-socketcan_ folder after installation. The sample configuration file is named socketcan.json.


## How to build the driver

You need _build-essentials_ and _git_ installed on your system

```bash
sudo apt update && sudo apt -y upgrade
sudo apt install build-essential git
```

To build this driver you to clone the driver source

```bash
git clone --recurse-submodules -j8 https://github.com/grodansparadis/vscpl2drv-socketcan.git
```

You also need to have the vscp main repository checkout at the same location as you checkout the driver. Do this with

```bash
git clone --recurse-submodules -j8 https://github.com/grodansparadis/vscp.git
```

The build used **pandoc** for man-page generation so you want the man pages you should install it first with

```
sudo apt install pandoc
```

If you skip it the build will give you some errors (which you can ignore if you don't care about the man page)

Now go into the repository and build the driver

```
cd vscpl2drv-socketcan
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/
make
sudo make install
```

Skip _"-DCMAKE_INSTALL_PREFIX=/"_ if you want the _"local"_ prefix to all install paths except for the driver.

If you want to generate binary packages issue

```bash
sudo cpack
```

Default install folder when you build from source is */var/lib/vscp/drivers/level2*. You can change this with the --prefix option in the make install step. For example 

```
make DESTDIR==/usr/local install
```

to install to */usr/local/var/lib/vscp/drivers/level2*.

## Configuration

#### VSCP daemon driver config

The VSCP daemon configuration file is (normally) located at */etc/vscp/vscpd.json* (For the curious: [VSCP daemon full sample config file for Linux](https://github.com/grodansparadis/vscp/blob/master/resources/linux/vscpd.json)). To use the vscpl2drv-socketcan.so driver there must be an entry in the drivers level2 section

```json
"drivers" : {
  "level2" : [
```

with the following format

```json
{
  "enable" : true,
  "name" : "socketcan",
  "path-driver" : "/var/lib/vscp/drivers/level2/libvscpl2drv-socketcan.so",
  "path-config" : "/etc/vscp/socketcan.json",
  "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:33:33:00:00:00:00:00:00",

  "mqtt": {
    "bind": "",
    "host": "test.mosquitto.org",
    "port": 1883,
    "mqtt-options": {
      "tcp-nodelay": true,
      "protocol-version": 311,
      "receive-maximum": 20,
      "send-maximum": 20,
      "ssl-ctx-with-defaults": 0,
      "tls-ocsp-required": 0,
      "tls-use-os-certs": 0
    },
    "user": "vscp",
    "password": "secret",
    "clientid": "the-vscp-daemon",
    "publish-format": "json",
    "subscribe-format": "auto",
    "qos": 1,
    "bcleansession": false,
    "bretain": false,
    "keepalive": 60,
    "bjsonmeasurementblock": true,
    "topic-daemon-base": "vscp-daemon/{{guid}}/",
    "topic-drivers": "drivers",
    "topic-discovery": "discovery",
    "reconnect": {
      "delay": 2,
      "delay-max": 10,
      "exponential-backoff": false
    },
    "tls": {
      "cafile": "",
      "capath": "",
      "certfile": "",
      "keyfile": "",
      "pwkeyfile": "",
      "no-hostname-checking": true,
      "cert-reqs": 0,
      "version": "",
      "ciphers": "",
      "psk": "",
      "psk-identity": ""
    },
    "will": {
      "topic": "vscp-daemon/{{srvguid}}/will",
      "qos": 1,
      "retain": true,
      "payload": "VSCP Daemon is down"
    },
    "subscribe" : [
      {
        "topic": "remote-vscp/{{guid}}/#",
        "qos": 0,
        "v5-options": 0,
        "format": "auto"
      }
    ],
    "publish" : [
      {
        "topic": "vscp/{{guid}}/{{class}}/{{type}}/{{nodeid}}",
        "qos": 1,
        "retain": false,
        "format": "json"
      }
    ]
  }
}
```

##### enable
Set enable to "true" if the driver should be loaded by the VSCP daemon.

##### name
This is the name of the driver. Used when referring to it in different interfaces.

##### path-driver
This is the path to the driver. If you install from a Debian package this will be */var/lib/vscp/drivers/level2/libvscpl2drv-socketcan.so*.

##### path-config
This is the path to the driver configuration file (see below). This file determines the functionality of the driver. A good place for this file is in _/etc/vscp/socketcan.json_ It should be readable only by the user the VSCP daemon is run under (normally _vscp_) as it holds credentials to log in to a remote VSCP tcp/ip link interface. Never make it writable at this location.

##### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html). The tool [vscp_eth_to_guid](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=think-before-guid) is a useful tool that is shipped with the VSCP daemon that will get you a unique GUID if you are working on a machine with an Ethernet interface.

##### mqtt
See the [VSCP configuration documentation](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=config-mqtt) for info about this section. It is common for all drivers.


## Configuring the driver

On start up the configuration is read from the path set in the driver configuration of the VSCP daemon, usually */etc/vscp/conf-file-name* and values are set from this location. If the **write** parameter is set to "true" the above location is a bad choice as the VSCP daemon will not be able to write to it. A better location is */var/lib/vscp/drivername/configure-name.json* or some other writable location.

The configuration file have the following format

```json
{
  "debug" : true,
  "write" : false,
  "interface": "vcan0",
  "flags": 0,
  "key-file": "/var/vscp/vscp.key",
  "encryption" : "none|aes128|aes192|aes256",
  "logging": {
    "console-enable": true,
    "console-level": "trace",
    "console-pattern": "[vcpl2drv-socketcan %c] [%^%l%$] %v",
    "file-enable": true,
    "file-log-level": "debug",
    "file-log-path" : "/var/log/vscp/vscpl1drv-socketcan.log",
    "file-log-pattern": "[vcpl2drv-socketcan %c] [%^%l%$] %v",
    "file-log-max-size": 50000,
    "file-log-max-files": 7
  }, 
  "filter" : {
    "in-filter" : "incoming filter on string form",
    "in-mask" : "incoming mask on string form",
    "out-filter" : "outgoing filter on string form",
    "out-mask" : "outgoing mask on string form"
  }
}
```

### debug
Set debug to _true_ to get debug information written to the log file. This can be a valuable help if things does not behave as expected.

### write
If write is true dynamic changes to the configuration file will be possible to save dynamically to disk. That is, settings you do at runtime can be saved and be persistent. The safest place for a configuration file is in the VSCP configuration folder */etc/vscp/* but for dynamic saves are not allowed if you don't run the VSCP daemon as root (which you should not). Next best place is to use the folder */var/lib/vscp/drivers/level2/configure.json*. A default configuration file is written to [/usr/share/vscp/drivers/level2/vscpl2drv-socketcan](/usr/share/vscp/drivers/level2/vscpl2drv-socketcan) when the driver is installed.

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder is a good choice.

### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html).

### Interface

> interface  (For example can0/can1/can2...)

The parameter interface is the socketcan interface to use. Typically this is can0, can0, can1... Defaults is vcan0 the first virtual interface. If the variable prefix_interface is available it will be used instead of the configuration value.

### Flags
This is configuration flags for the socketcan interface. Currently not used.

### key-file 
Path to file with encryption key. Currently not used.

### encryption
Encryption used. Currently not used.

### Logging

Options for driver logging is set here.

#### console-enable 
Set to _true_ to log to the console.

#### console-level
Logging level for console log. Set to one of "off | critical | error | warn | info | debug | trace". 

#### console-pattern
The logging pattern for the console. The default is

```
"[vcpl2drv-socketcan] [%^%l%$] %v"
```
Patterns are described [here](https://spdlog.docsforge.com/v1.x/3.custom-formatting/#pattern-flags).

#### file-enable 
Set to _true_ to log to the console.

#### file-level
Set to one of "off | critical | error | warn | info | debug | trace" to set log level.

#### file-path" : "path to log file",
This is a writable path to a file that will get log information written to it. This can be a valuable to have if things does not behave as expected.

#### file-pattern
The logging pattern for the console. The default is

```
"[vcpl2drv-socketcan] [%^%l%$] %v"
```
Patterns are described [here](https://spdlog.docsforge.com/v1.x/3.custom-formatting/#pattern-flags).

#### file-max-size
Max size for log file before it will rotate and a new file is created. Default is 5 Mb.

#### file-max-files
Max number of log files to keep. Default is 7


### Filter
Main filter for incoming and outgoing events. Default is to send and receive all events. The truth table for VSCP filter/masks is described [here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_decision_matrix?id=truth-table-for-filtermask).

Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

**Default**: setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the [vscpd manual](http://grodansparadis.github.io/vscp/#/) for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

#### mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

#### in-filter
Incoming filter on string form. The string filter has the form _"filter-priority, filter-class, 
    filter-type, filter-GUID"_

#### in-mask
Incoming mask on string form. The string mask has the form _"mask-priority, 
    mask-class, mask-type, mask-GUID”_.

#### out-filter
Outgoing filter on string form. The string filter has the form _"filter-priority, filter-class, 
    filter-type, filter-GUID"_

#### out-mask
Outgoing mask on string form. The string mask has the form _"mask-priority, 
    mask-class, mask-type, mask-GUID”_.


## Using the vscpl2drv-socketcan driver

The easiest way to test the vscpl2drv-socketcan driver is to create a virtual CAN interface. You should first of all make sure that the necissary modules are loaded on your system. You do this with

```bash
modprobe can
modprobe can_raw
modprobe can-bcm
modprobe can-dev
modprobe can-gw
modprobe vcan
```

Then you should create the virtual CAN interface. You can do this with

```bash
sudo ip link add dev vcan0 type vcan
```

or if you want a CAN FD interface

```bash
ip link add dev vcan0 type vcan
ip link set vcan0 mtu 72
```

Then you have to bring up the virtual interface

```
sudo ip link set up vcan0
```

You can use

```bash
ip link show
```

to display information about your interfaces.

With 

```
candump vcan0
```

you can check CAN frames sent on this interface. 

You can use [cansend]() to send frames to the interface

```
cansend vcan0 0000eb00#0011
```

or send random data with

```
cangen -e -f vcan0 -v vcan0
```

Remember that VSCP only use extended CAN frames (the **-e** switch). Here we also use the **-f** switch to enable CAN FD frames.

You have a good tutorial [here](https://sgframework.readthedocs.io/en/latest/cantutorial.html) describing the use of the virtual CAN interface.

To connect to a real CAN bus you need a CAN adapter like [TouCAN](https://www.rusoku.com/products). There are other adapters to of course but I list (and recommend) TouCAN here because _Gediminas Simanskis_ the guy who has made it, has been around VSCP for many, many years now and on top of this is one of the best hardware engineers I know in the world.


[This is a link](https://wiki.st.com/stm32mpu/wiki/How_to_set_up_a_SocketCAN_interface) to some info about setting up a real world CAN interface. But search on _socketcan_ and you will find plenty of information. 


---

## Other sources with information

  * The VSCP site - https://www.vscp.org
  * The VSCP document site - https://docs.vscp.org/
  * VSCP discussions - https://github.com/grodansparadis/vscp/discussions

---

## Copyright
Copyright (C) 2000-2021 Åke Hedman, The VSCP Project - MIT license.
