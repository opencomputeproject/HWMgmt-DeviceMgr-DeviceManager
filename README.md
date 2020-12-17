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

# Device-Management Repository

This Repo contains the code for Device-Manager and related functionality. Device-manager is module which collects the
device data from the devices which support REDFISH and publishes onto kafka bus. User-application is another software
which listens on kafka bus and makes the data available to the dashboard for user.

# Device Manager Platform

Device Manager gets the device details from devices and periodicaly collects data using REDFISH RESTful APIS based on HTTP.
The interface (gRPC) is between Device-Manager and user-application. Device-Manager also registers specific Redfish APIs for
events from the device like alerts, removal/insertion events. It then publishes data on kafka bus to collect the data.

# Co-Work with Edgecore PSME and OpenBMC Redfish
```
+-----------------------------+
|   Edgecore Device Manager   |
+-------------+-------------+-+
    |        |          |
    |        |          |
+---v--+ +---v----+ +---v-----+
| VOLT | | SWITCH | | OpenBMC |
| PSME | |  PSME  | | Redfish |
+------+ +--------+ +---------+
```
The Edgecore Device Manager could manage a wide range of devices (ex: Edgecore XGS-PON/GPON vOLTs, ONL/SONIC Switches, and OpenBMC device).$
Before you use the Device Manager, you have to install the PSME software to the device.
More detailed information can be found at [DM-Redfish-PSME](https://github.com/opencomputeproject/DM-Redfish-PSME) and [DM-Redfish-OpenBMC](https://github.com/opencomputeproject/DM-Redfish-OpenBMC).

# Preparation
The host system need to install necessory packages (ex: git, curl and docker)

```shell
sudo apt update
sudo apt upgrade
sudo apt install git curl unzip
```

# Installation Procdures

## Install Kubernets environment
The device management based on the k8s environment to corprate with others PODs (ex: core-kafka-0).

```shell
make install-docker
After this command, you need to logout/reboot the host system to take effect on the running system
```
```shell
Before this command, you need to add the "nameserver" variable (ex: nameserver 8.8.8.8) to "/etc/resolv.conf"
make k8s
```
Optionally, To avoid conflicting the Calic IP to host a range of the subnet. You could this option to point Calic IP subnet.
(Default: 192.168.0.0/16, ex: CALICO_IPAM=172.17.0.0/16)
```shel
CALICO_IPAM=<IP/Subnet> make k8s
```
After installed the k8s Pods, you could use the command to check the status of Pods.
```text
> make status
NAMESPACE     NAME                                     READY   STATUS    RESTARTS   AGE
default       cord-kafka-0                             1/1     Running   1          19h
default       cord-kafka-zookeeper-0                   1/1     Running   0          19h
kube-system   calico-node-xnrw6                        2/2     Running   0          19h
kube-system   coredns-bb49df795-65pwv                  1/1     Running   0          19h
kube-system   coredns-bb49df795-b22tb                  1/1     Running   0          19h
kube-system   etcd-device-manager                      1/1     Running   0          19h
kube-system   kube-apiserver-device-manager            1/1     Running   0          19h
kube-system   kube-controller-manager-device-manager   1/1     Running   0          19h
kube-system   kube-proxy-lbhvc                         1/1     Running   0          19h
kube-system   kube-scheduler-device-manager            1/1     Running   0          19h
kube-system   tiller-deploy-66478cb847-4l5fv           1/1     Running   0          19h
```

## Download and build Device management docker image
The images of device management will be downloaded to the host, And build those source files.

The following by this command to build the Device Management docker image
```shell
make build-dm
```
```shell
If you encountered that fails to download images, you need to use this command to fix it.
sudo systemctl restart docker
```

## Install Device management Pod.
The device management would follow commands to bring up the Pod.

Bring up the Device Persistent Volume first (Default: /var/devices_data) . The device data file could store in the host platform.
```shell
make dpv
```
```text
Displaying the device persisent volume status
> helm ls
NAME            REVISION        UPDATED                         STATUS          CHART                           APP VERSION     NAMESPACE
cord-kafka      1               Wed Nov 11 18:28:40 2020        DEPLOYED        kafka-0.13.3                    5.0.1           default
devices-pv      1               Wed Nov 11 20:47:46 2020        DEPLOYED        local-directory-0.1.0-dev0                      default
```
Bring up the Device-management Pod
```shell
make dm
```
```text
After bring up the Pods, you could use the command to check the status of device management Pod.
> make status | grep device-management
default       device-management-67846fcdd9-8vsfk       1/1     Running   0          72s
```

## Unload Device Persistent Volume and Device Management Pod
The command is unloading the device persistent volume helm chart.
```shell
make clean-dpv
```
The command is unloading the device mangement pod.
```shell
make clean-dm
```

# Build and run the demotest
Before you build the demotest tool, Some of packages needs to install, For example: go packages
```shell
cd demo_test
make go-install
```
Take effect Go environment variables
```shell
. ~/.bashrc
```
Install Go APIs and "protoc" tool.
```shell
cd demo_test
make prereq
```
The demotest is a daemon that create the connection interface for accessing the device.
```shell
cd demo_test
make demotest
```
After built the demotest, You could run the daemon in the foreground and listen by the "dm" program command.
```text
cd demo_test
./demotest
2020/09/09 14:51:00 Configuration:
2020/09/09 14:51:00     Kafka: kafka_ip.sh
2020/09/09 14:51:00     Listen Address: :9999
INFO[09-09-2020 14:51:00] Launching server...
INFO[09-09-2020 14:51:00] kafkaInit starting
INFO[09-09-2020 14:51:00] IP address of kafka-cord-0:192.168.0.6:9092
INFO[09-09-2020 14:51:00] Starting topicListener for importer
```
# Test physical devices
The automation test needs two physical devices to perform the test cases that include getting device data and functionalities.
## Automation Test
Test cases utilizing 'dm' provided in the functional_test/ sub-directory. The test results will save a tarball file and locates in the "results" directory. They can execute those test cases through Makefile
```shell
cd demo_test/functional_test
make test IP1=<ip of 1st device> PORT1=<RF port of 1st device> IP2=<ip of 2nd device> PORT2=<RF port of 2nd device> USER1=<user of 1st device> PWD1=<password of 1st device> USER2=<user of 2nd device> PWD2=<password of 2nd device>
```
The test case could specific by the "TESTSDIR" option (for exmaple: tests/account_service)
```shell
cd demo_test/functional_test
make test IP1=<ip of 1st device> PORT1=<RF port of 1st device> IP2=<ip of 2nd device> PORT2=<RF port of 2nd device> USER1=<user of 1st device> PWD1=<password of 1st device> USER2=<user of 2nd device> PWD2=<password of 2nd device> TESTSDIR=<test case directory>
```
## Manual testing at command line
The 'dm' test tool needs to build at the command line the following by
```shell
cd demo_test/functional_test
make
```
For running 'dm', please make and launch 'demotest' first.

# Reset k8s environment
The command is removing all pods and helm chart.
```shell
make make reset-pods
```
