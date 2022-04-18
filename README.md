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
The Edgecore Device Manager could manage a wide range of devices (ex: Edgecore XGS-PON/GPON vOLTs, ONL/SONIC Switches, and OpenBMC device).
Before you use the Device Manager, you have to install the PSME software to the device.
More detailed information can be found at [DM-Redfish-PSME](https://github.com/opencomputeproject/DM-Redfish-PSME) and [DM-Redfish-OpenBMC](https://github.com/opencomputeproject/DM-Redfish-OpenBMC).

# Preparation
The Device Manager supports running the *Ubuntu Desktop 16.04 version*. And the hardware platform needs to match the minimum requirement,
such as *CPU 2 cores/Memory 4GB and SSD driver 40GB*. The host system need to install necessory packages (ex: git, curl and docker)

# Quickly Installation Procedures
## Install Device Manager using the One-Time-Finish command
The One-Time-Finish command is installing Device Manager when you build the Device Manager environment first time in the
Ubuntu 16/18/20 Desktop/Servcer platform. This command will install the necessary packages and commands. It also will build Device Manager containers.

```shell
#> make all
```

## Reinstall Device Manager using the One-Time-Finish command
The One-Time-Finish command is reinstalling Device Manager after you have installed the Device Manager the first time.
This command does not install packages and commands. Because you have installed already with those commands before.
(If the device manager platform has rebooted, you need to perform this command again)

```shell
#> make install
```
After the One-Time-Finish command, you could use Device Manager to manage your devices.

# Installation Procedures with step by step
(If you used the quickly installation procedures as above, you could ingore those steps)
## Install Kubernets environment

```shell
#> sudo apt update
#> sudo apt upgrade
#> sudo apt install git curl unzip
```

The device management based on the k8s environment to corprate with others PODs (ex: core-kafka-0).

```shell
#> make /usr/bin/docker
```

```shell
#> make k8s
```

After installed the k8s Pods, you could use the command to check the status of Pods.
```text
#> make status
kubectl get pods --all-namespaces -o wide
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE     IP                NODE             NOMINATED NODE   READINESS GATES
kube-system   calico-kube-controllers-7c5dd46f7d-49cp9   1/1     Running   0          5h26m   192.168.253.132   device-manager   <none>           <none>
kube-system   calico-node-tbqg7                          1/1     Running   0          5h26m   172.17.8.49       device-manager   <none>           <none>
kube-system   coredns-558bd4d5db-hs5g5                   1/1     Running   0          5h26m   192.168.253.131   device-manager   <none>           <none>
kube-system   coredns-558bd4d5db-kr2nb                   1/1     Running   0          5h26m   192.168.253.133   device-manager   <none>           <none>
kube-system   etcd-device-manager                        1/1     Running   0          5h27m   172.17.8.49       device-manager   <none>           <none>
kube-system   kube-apiserver-device-manager              1/1     Running   0          5h27m   172.17.8.49       device-manager   <none>           <none>
kube-system   kube-controller-manager-device-manager     1/1     Running   0          5h27m   172.17.8.49       device-manager   <none>           <none>
kube-system   kube-proxy-rcvjd                           1/1     Running   0          5h26m   172.17.8.49       device-manager   <none>           <none>
kube-system   kube-scheduler-device-manager              1/1     Running   0          5h27m   172.17.8.49       device-manager   <none>           <none>
manager       cord-kafka-0                               1/1     Running   1          5h26m   192.168.253.130   device-manager   <none>           <none>
manager       cord-kafka-zookeeper-0                     1/1     Running   0          5h26m   192.168.253.129   device-manager   <none>           <none>
```

## Go package Installation
The go command will use in building the Device Manager source codes.
```shell
#> make go-install
```

```shell
#> . ~/.bashrc      #Take effect Go environment variables
```

## Protobuf package installation and download the necessary GO libraries.
The protoc command will use in building the .proto file.
```shell
#> make prereq
```

## Download and build Device management docker image
The images of device management will be downloaded to the host, And build those source files.

The following by this command to build the Device Management docker image
```shell
#> make build-dm
```

## Install Device management Pod.
The device management would follow commands to bring up the Pod.

Bring up the Device Persistent Volume first (Default: /var/devices_data) . The device data file could store in the host platform.
```shell
#> make dpv
```

Displaying the device persisent volume status
```shell
#> helm ls
```
NAME            REVISION        UPDATED                         STATUS          CHART                           APP VERSION     NAMESPACE
cord-kafka      1               Wed Nov 11 18:28:40 2020        DEPLOYED        kafka-0.13.3                    5.0.1           default
devices-pv      1               Wed Nov 11 20:47:46 2020        DEPLOYED        local-directory-0.1.0-dev0                      default


Bring up the Device-management Pod
```shell
#> make dm
```

After bring up the Pods, you could use the command to check the status of device management Pod.
```text
#> make status | grep device-management
manager       device-management-64b45fd858-477fv       1/1     Running   0          4h25m   192.168.0.12   device-manager   <none>
```

## Unload Device Persistent Volume and Device Management Pod
The command is unloading the device persistent volume helm chart.
```shell
#> make clean-dpv
```
The command is unloading the device mangement pod.
```shell
#> make clean-dm
```

# Build and run the demotest
Before you build the demotest tool, Some of packages needs to install, For example: go packages.
You do not run this command if you already install go packages.
```shell
#> cd demo_test
#> make go-install
```
Take effect Go environment variables
```shell
#> . ~/.bashrc
```
Install Go APIs and "protoc" tool.
You do not run this command if you already install "protoc" tool.
```shell
#> cd demo_test
#> make prereq
```
The demotest is a daemon that create the connection interface for accessing the device.
```shell
#> cd demo_test
#> make demotest
```
After built the demotest, You could run the daemon in the foreground and listen by the "dm" program command.
```text
#> cd demo_test
#> ./demotest
2020/09/09 14:51:00 Configuration:
2020/09/09 14:51:00     Kafka: kafka_ip.sh
2020/09/09 14:51:00     Listen Address: :9999
INFO[09-09-2020 14:51:00] Launching server...
```

```text
#> cd demo_test
#> ./demotest -s -t kafka_topic
2020/09/09 14:51:00 Configuration:
2020/09/09 14:51:00     Kafka: kafka_ip.sh
2020/09/09 14:51:00     Listen Address: :9999
INFO[09-09-2020 14:51:00] Launching server...
INFO[09-09-2020 14:51:00] kafkaInit starting
INFO[09-09-2020 14:51:00] IP address of kafka-cord-0: 192.168.253.130:9092
INFO[09-09-2020 14:51:00] Starting topicListener for kafka_topic
```

# Test physical devices
The automation test needs two physical devices to perform the test cases that include getting device data and functionalities.

## Automation Test
Test cases utilizing 'dm' provided in the functional_test/ sub-directory. The test results will save a tarball file and locates in the "results" directory. They can execute those test cases through Makefile
```shell
#> cd demo_test/functional_test
#> make test IP1=<ip of 1st device> PORT1=<RF port of 1st device> IP2=<ip of 2nd device> PORT2=<RF port of 2nd device>


# Test physical devices
The automation test needs two physical devices to perform the test cases that include getting device data and functionalities.

## Automation Test
Test cases utilizing 'dm' provided in the functional_test/ sub-directory. The test results will save a tarball file and locates in the "results" directory. They can execute those test cases through Makefile
```shell
#> cd demo_test/functional_test
#> make test IP1=<ip of 1st device> PORT1=<RF port of 1st device> IP2=<ip of 2nd device> PORT2=<RF port of 2nd device>
             USER1=<user of 1st device> PWD1=<password of 1st device> USER2=<user of 2nd device> PWD2=<password of 2nd device>
```
The test case could specific by the "TESTSDIR" option (for exmaple: tests/account_service)
```shell
#> cd demo_test/functional_test
#> make test IP1=<ip of 1st device> PORT1=<RF port of 1st device> IP2=<ip of 2nd device> PORT2=<RF port of 2nd device>
             USER1=<user of 1st device> PWD1=<password of 1st device> USER2=<user of 2nd device> PWD2=<password of 2nd device>
             TESTSDIR=<test case directory>
```
## Manual testing at command line
The 'dm' test tool needs to build at the command line the following by
```shell
#> cd demo_test/functional_test
#> make dm
```
For running 'dm', please make and launch 'demotest' first.
If you want to know the user manual, please read the 'demo_test/functional_test/README'

# Reset k8s environment
The command is removing all pods and helm chart.
```shell
#> make reset-pods
```
