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
## Nagios integrate with Device Manager

### Purpose
Nagios is used to monitor device information such as device chassis, thermal, power information. We integrated Nagios with Device Manager which use gRPC API to collect device information. Nagios gets the device information from Device Manage by gRPC and display on its UI.

### Nagios installation and configuration
By executing the script install-dashboard.sh. It will automatically install and configure Nagios core, deploy a customized UI for demostration. 

#### 1. Excute instann-dashboard.sh
```
$ cd nagios-dashboard
$ bash install-dashboard.sh
```
#### 2. Input Device Manager server and device IP addresses
Before input the IP address.Please make sure the Device Manager server and device IP addresses are connectable.

Example:
- Device Manager IP: 192.168.8.41
- Device IP: 192.168.8.10
```
$ bash install-dashboard.sh
Input Device Manager server IP address:
192.168.8.41
Testing DEVICE_MANGER_SERVER_IP: 192.168.8.41 ....
Input Device IP address:
192.168.8.10
```

#### 3. Input nagios administrator password
Default administrator username is **nagiosadmin**. Input and confirm the password.
```
Module rewrite already enabled
Module cgi already enabled
sudo htpasswd -c /usr/local/nagios/etc/htpasswd.users nagiosadmin
New password:
Re-type new password:
```
#### 4. Update Python version
**If Python3 version is too old, the following message will be popup. Please select number 2 to choice Python3.8.**
```
There are 2 choices for the alternative python3 (providing /usr/bin/python3).

  Selection    Path                Priority   Status
------------------------------------------------------------
* 0            /usr/bin/python3.8   2         auto mode
  1            /usr/bin/python3.6   1         manual mode
  2            /usr/bin/python3.8   2         manual mode

Press <enter> to keep the current choice[*], or type selection number:
```
#### 5. Open browser and login Nagios
Once Nagios installation is finished. Open browser and type the URL http://[nagios-host-ip]/nagios. And then Input the account **nagiosadmin** and password that inputted  in step 3.


