<!--
Edgecore DeviceManager
Copyright 2020-2021 Edgecore Networks, Inc.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

```text
'dm' is a command line wrapper of the test application 'demotest' serving the purpose of device-management API functional testing.

It runs on top of the device-management container and 'demotest' requiring the accessibility of at least 2 separate devices running
RedFish servers and can be utilized in either automated or manual testing. Either way, the device-mangement container needs to have
been deployed.
```

# Test Automation
   Test cases utilizing 'dm' are provided in the tests/ sub-directory. They can be executed through either the Makefile is provided.

   At command line, type
```shell
   make test IP1=<ip of 1st device> PORT1=<RF port # of 1st device> IP2=<ip of 2nd device> PORT2=<RF port # of 2nd device>
             USER1=<user of 1st device> PWD1=<password of 1st device> USER2=<user of 2nd device> PWD2=<password of 2nd device>
```

   Optionally, The "EXTERNAL=y" parameter is testing the stanadard OCP functionality. It needs to install standard PSME software
   to device.
```shell
   make test IP1=<ip of 1st device> PORT1=<RF port # of 1st device> IP2=<ip of 2nd device> PORT2=<RF port # of 2nd device>
             USER1=<user of 1st device> PWD1=<password of 1st device> USER2=<user of 2nd device> PWD2=<password of 2nd device> EXTERNAL=y
```

# Manual testing at command line
   To build 'dm', at command line, type
```shell
	make
```

# Manual Test
  To run 'dm', please make and launch 'demotest' first then follow the syntax and examples below.

## register one device
Example: Set IP 192.168.4.27, port 8888, freq 180, device network detection 1
```shell
./dm attach 192.168.4.27:8888:180:1
```

## register multiple devices
Example: Set "IP 192.168.4.27 port 8888, freq 180, device network detection 1" and
             "IP 192.168.4.26 port 8888 freq 120, device network detection 0"
```shell
./dm attach 192.168.4.27:8888:180:1 192.168.4.26:8888:120:0
```

## set session service
Example 1: Set IP 192.168.4.27, enable to session service, session timeout 600
```shell
./dm setsessionservice 192.168.4.27:8888:"":1:600
```
Example 2: Set IP 192.168.4.27, disable to session service, session timeout 600
```shell
./dm setsessionservice 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:0:600
```

## login device
Example: IP 192.168.4.27, username admin, password redfish
```shell
./dm logindevice 192.168.4.27:8888:admin:redfish
```

## detach devices
Example: Delete IP 192.168.4.27
```shell
./dm detach 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## Change polling interval
Example:
Set frequecny to 30 seconds
```shell
./dm period 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:30
```

## Get Current List of Devices monitored
```shell
./dm showdevices
```

## Create an device account (User Privileges: Administrator/Operator/ReadOnlyUser)
Example: IP: 192.168.4.27 and port: 8888, username: user_name, password: user_password , user privilege: Operator
```shell
./dm createaccount 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:user_name:user_password:Operator
```

## Delete an device account
Example: IP: 192.168.4.27 and port: 8888, username: user_name
```shell
./dm deleteaccount 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:user_name
```

## Change an device account password
Example: IP: 192.168.4.27 and port: 8888, username: user_name, new password: user_passowrd
```shell
./dm changeuserpassword 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:user_name:user_password
```

## logout device
Example: IP: 192.168.4.27 and port: 8888, username: user_name
```shell
./dm logoutdevice 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:user_name
```

## start to query device data
Example: IP: 192.168.4.27 and port: 8888
```shell
./dm startquerydevice 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## stop to query device data
Example: IP: 192.168.4.27 and port: 8888
```shell
./dm stopquerydevice 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## show device accounts
Example: IP: 192.168.4.27 and port: 8888
```shell
./dm sdeviceaccountslist 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## add Redfish API to poll device data periodically
Example: IP: 192.168.4.27 and port: 8888, Redfish API: /redfish/v1/Managers
```shell
./dm addpollingrfapi 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:/redfish/v1/Managers
```

## remove Redfish API to poll device data periodically
Example: IP: 192.168.4.27 and port: 8888, Redfish API: /redfish/v1/Managers
```shell
./dm removepollingrfapi 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:/redfish/v1/Managers
```

## show added Redfish API to poll device data periodically
Example: IP: 192.168.4.27 and port: 8888
```shell
./dm getpollingrflist 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## enable log service to device
Example: IP: 192.168.4.27 and port: 8888, enable log service: 1
```shell
./dm setlogservice 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:1
```

## disable log service to device
Example: IP: 192.168.4.27 and port: 8888, disable log service: 0
```shell
./dm setlogservice 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:0
```

## reset all log data to device
Example: IP: 192.168.4.27 and port: 8888
```shell
./dm resetlogdata 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## get all log data to device (maximum data count: 1000)
Example: IP: 192.168.4.27 and port: 8888
```shell
./dm getdevicelogdata 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## get device reset system type
Example: IP: 192.168.4.27 and port: 8888
```shell
./dm getdeviceresettype 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## reset device system (supported reset type is "GracefulRestart". BMC supports "ForceOn", "ForceOff" and "ForceReset")
Example: IP: 192.168.4.27 and port: 8888, reset type: GracefulRestart
```shell
./dm resetdevicesystem 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:GracefulRestart
```

## get device tempertures infomation
Example: IP: 192.168.4.27 and port: 8888
```shell
./dm getdevicetemperaturedata 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24
```

## configure the device event temperature
Example: IP: 192.168.4.27 and port: 8888, member (sensor) id: 1, upper threshold non-critical temperature: 80,
         lower threshold non-critical temperature: 75
```shell
./dm setdevicetemperaturedata 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:1:80:75
```

## get device data from cache
Example: IP: 192.168.4.27 and port: 8888, Redfish API: /redfish/v1/Chassis/1
```shell
./dm getdevicedata 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:/redfish/v1/Managers/1
```

## access device data by Redfish API
Example: IP: 192.168.4.27 and port: 8888, Redfish API: /redfish/v1/Managers/1
```shell
./dm getdevicedata 192.168.4.27:8888:36b22b37ece56d5e00b7b2200df71c24:GET:/redfish/v1/Managers/1:""
```
