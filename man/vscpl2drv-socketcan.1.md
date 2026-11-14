% VSCPL2DRV-SOCKETCAN(1) VSCP Level II driver
% Åke Hedman, Grodans Paradis AB
% November 2026

# NAME

vscpl2drv-socketcan - connect VSCP to a SocketCAN interface

# SYNOPSIS

**libvscpl2drv-socketcan.so** (Linux), **vscpl2drv-socketcan.dll** (Windows), **libvscpl2drv-socketcan.dylib** (macOS)

A VSCP Level II driver. It is loaded by the VSCP daemon (**vscpd**(8)), VSCP Works or any other program that uses the VSCP Level II driver API, and is configured with the JSON configuration file described below. The path of the configuration file is given to the driver when it is opened (**path-config** in the daemon's driver configuration).

# DESCRIPTION

Socketcan level II driver

This driver interface SocketCAN, the official CAN API of the Linux kernel, has been included in the kernel for a long time now. Meanwhile, the official Linux repository has device drivers for all major CAN chipsets used in various architectures and bus types. SocketCAN offers the user a multiuser capable as well as hardware independent socket-based API for CAN based communication and configuration. Socketcan nowadays give access to the major CAN adapters that is available on the market. Note that as CAN only can handle Level I events only events up to class < 1024 can be sent to this device. Other events will be filtered out.

The driver supports CAN FD but the way id's are mapped in VSCP over CAN the use of bigger data counts are not just meaningful as they only is available in VSCP level II and the space for vscp class and vscp type is limited.

# CONFIGURATION

### VSCP MQTT daemon (vscp-mqtt-daemon) driver config

The VSCP MQTT daemon configuration file is (normally) located at */etc/vscp/vscpd.json* (For the curious: [VSCP daemon full sample config file for Linux](https://github.com/grodansparadis/vscp/blob/master/resources/linux/vscpd.json)). To use the vscpl2drv-socketcan.so driver there must be an entry in the drivers level2 section

```json
"drivers" : {
  "level2" : [
```

with the following format

```json
{
  "enable" : true,
  "name" : "socketcan",
  "path-driver" : "/path/do/driver/libvscpl2drv-socketcan.so",
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

#### enable
Set enable to "true" if the driver should be loaded by the VSCP daemon.

#### name
This is the name of the driver. Used when referring to it in different interfaces.

#### path-driver
This is the path to the driver. If you install from a Debian package this will be */var/lib/vscp/drivers/level2/libvscpl2drv-socketcan.so*.

#### path-config
This is the path to the driver configuration file (see below). This file determines the functionality of the driver. A good place for this file is in _/etc/vscp/socketcan.json_ It should be readable only by the user the VSCP daemon is run under (normally _vscp_) as it holds credentials to log in to a remote VSCP tcp/ip link interface. Never make it writable at this location.

#### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html). The tool [vscp_eth_to_guid](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=think-before-guid) is a useful tool that is shipped with the VSCP daemon that will get you a unique GUID if you are working on a machine with an Ethernet interface.

#### mqtt
See the [VSCP configuration documentation](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=config-mqtt) for info about this section. It is common for all drivers.

### VSCP tcp/ip daemon (vscp-tcpip-daemon) driver config

```json
{
  {
    "enable": true,
    "name": "socketcan",
    "path-driver": "/path/to/driver/libvscpl2drv-socketcan.so",
    "path-config": "/etc/vscp/socketcan.json",
    "guid": "FF:FF:FF:FF:FF:FF:FF:F5:02:00:00:00:00:00:00:03"
  }
}
```

#### enable
Set enable to "true" if the driver should be loaded by the VSCP daemon.

#### name
This is the name of the driver. Used when referring to it in different interfaces.

#### path-driver
This is the path to the driver. If you install from a Debian package this will be */var/lib/vscp/drivers/level2/libvscpl2drv-socketcan.so*.

#### path-config
This is the path to the driver configuration file (see below). This file determines the functionality of the driver. A good place for this file is in _/etc/vscp/socketcan.json_ It should be readable only by the user the VSCP daemon is run under (normally _vscp_) as it holds credentials to log in to a remote VSCP tcp/ip link interface. Never make it writable at this location.

#### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html). The tool [vscp_eth_to_guid](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=think-before-guid) is a useful tool that is shipped with the VSCP daemon that will get you a unique GUID if you are working on a machine with an Ethernet interface.

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

## debug
Set debug to _true_ to get debug information written to the log file. This can be a valuable help if things does not behave as expected.

## write
If write is true dynamic changes to the configuration file will be possible to save dynamically to disk. That is, settings you do at runtime can be saved and be persistent. The safest place for a configuration file is in the VSCP configuration folder */etc/vscp/* but for dynamic saves are not allowed if you don't run the VSCP daemon as root (which you should not). Next best place is to use the folder */var/lib/vscp/drivers/level2/configure.json*. A default configuration file is written to /usr/share/vscp/drivers/level2/vscpl2drv-socketcan when the driver is installed.

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder is a good choice.

## guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html).

## Interface

> interface  (For example can0/can1/can2... vacan0, vcan1, vcan2...)

The parameter interface is the socketcan interface to use. Typically this is can0, can0, can1... Defaults is vcan0 the first virtual interface. If the variable prefix_interface is available it will be used instead of the configuration value.

## Flags
This is configuration flags for the socketcan interface. Currently not used.

## key-file 
Path to file with encryption key. Currently not used.

## encryption
Encryption used. Currently not used.

## Logging

Options for driver logging is set here.

### console-enable 
Set to _true_ to log to the console.

### console-level
Logging level for console log. Set to one of "off | critical | error | warn | info | debug | trace". 

### console-pattern
The logging pattern for the console. The default is

```
"[vcpl2drv-socketcan] [%^%l%$] %v"
```
Patterns are described [here](https://spdlog.docsforge.com/v1.x/3.custom-formatting/#pattern-flags).

### file-enable 
Set to _true_ to log to the console.

### file-level
Set to one of "off | critical | error | warn | info | debug | trace" to set log level.

### file-path" : "path to log file",
This is a writable path to a file that will get log information written to it. This can be a valuable to have if things does not behave as expected.

### file-pattern
The logging pattern for the console. The default is

```
"[vcpl2drv-socketcan] [%^%l%$] %v"
```
Patterns are described [here](https://spdlog.docsforge.com/v1.x/3.custom-formatting/#pattern-flags).

### file-max-size
Max size for log file before it will rotate and a new file is created. Default is 5 Mb.

### file-max-files
Max number of log files to keep. Default is 7

## Filter
Main filter for incoming and outgoing events. Default is to send and receive all events. The truth table for VSCP filter/masks is described [here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_decision_matrix?id=truth-table-for-filtermask).

Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

**Default**: setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the [vscpd manual](http://grodansparadis.github.io/vscp/#/) for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

### mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

### in-filter
Incoming filter on string form. The string filter has the form _"filter-priority, filter-class, 
    filter-type, filter-GUID"_

### in-mask
Incoming mask on string form. The string mask has the form _"mask-priority, 
    mask-class, mask-type, mask-GUID”_.

### out-filter
Outgoing filter on string form. The string filter has the form _"filter-priority, filter-class, 
    filter-type, filter-GUID"_

### out-mask
Outgoing mask on string form. The string mask has the form _"mask-priority, 
    mask-class, mask-type, mask-GUID”_.

# FILES

*/var/lib/vscp/drivers/level2/libvscpl2drv-socketcan.so*
:   The driver (Linux).

*resources/linux/socketcan.json*
:   Sample configuration in the source repository (installed with the driver).

# SEE ALSO

**vscpd**(8), **vscp-dump**(1), **vscp-send**(1), **vscpl2drv-socketcan**(1), **vscpl2drv-tcpipsrv**(1)

The source code and the full documentation: <https://github.com/grodansparadis/vscpl2drv-socketcan>

The VSCP specification: <https://grodansparadis.github.io/vscp-doc-spec>

# COPYRIGHT

Copyright 2000-2026 Åke Hedman, Grodans Paradis AB. See the LICENSE file of the driver.
