<!--
Device Manager

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

This repository contains the code for Device-Manager and related functionality.

# Device Manager Platform

Device Manager is module which collects the device data from the devices and publishes onto Kafka bus.
Device Manager registers for specific events from the device (e.g. alerts, removal/insertion events).

An user-application listens on Kafka bus and makes the data available to the dashboard for user.
A gRPC interface is also established between Device-Manager and user-application.

# Interaction with DM-PSME and OpenBMC Redfish
```
+-----------------------------+
|        Device Manager       |
+-------------+-------------+-+
    |        |          |
    |        |          |
+---v--+ +---v----+ +---v-----+
| VOLT | | SWITCH | | OpenBMC |
| PSME | |  PSME  | | Redfish |
+------+ +--------+ +---------+
```

The device can implement the Redfish Service on an out-of-band platform entity (e.g. BMC) or on an in-band entity (e.g software agent).

The Redfish Service should be conformant to the OCP Baseline Profile.
The [OCP Baseline profile](https://github.com/opencomputeproject/HWMgmt-OCP-Profiles) prescribes the required [Redfish interface](http://dmtf.org/redfish) support.

The Linux Foundation OpenBMC repository contains source for a BMC firmware image with is conformant to the OCP Baseline profile.

The [OCP DM-PSME repository](https://github.com/opencomputeproject/DM-Redfish-PSME) contains an software agent for a Linux OS.  The image has been used by Edgecore on their XGS-PON/GPON vOLTs and ONL/SONIC switches.

# Hardware and Software requirments
The Device Manager supports running the *Ubuntu Desktop 16.04 version*. And the hardware platform needs to match the minimum requirement,
such as *CPU 2 cores/Memory 4GB and SSD driver 40GB*. The host system need to install necessory packages (ex: git, curl and docker)

# Using the Makefile on Ubuntu

The following procedures work in Ubuntu 16/18/20 Desktop/Server environment.

## Build and Install Device Manager
The following command will: 1) build the Device Manager containers, 2) install Device Manager and 3) install the packages and commands. After the Once the command completes, Device Manager is ready manage the devices.

```
$> make all
```
## Reinstall Device Manager
If the Device Manager platform has rebooted, the Device Manager needs to be re-install.
The following command will re-install Device Manager.
This command will not install packages and commands. 

```
$> make install
```

## Install Kubernetes environment
The Device Manager is based on the k8s environment to corporate with others PODs (ex: core-kafka-0).

```
$> sudo apt update
$> sudo apt upgrade
$> sudo apt install git curl unzip
$> make /usr/bin/docker
$> make k8s
```

After installed the k8s Pods, the command can be used to check the status of Pods.

```text
$> make status
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

## Install Go package
The following command will install GoLang compile.

```shell
$> make go-install
$> . ~/.bashrc      #Take effect Go environment variables
```

## Install Protobuf
The following command shall install protoc.  protoc is use to build the .proto file.

```shell
$> make prereq
```

## Build Device Manager docker image
The following command will build the Device Manager docker image.

```shell
$> make build-dm
```

## Bring up Device Persistent Volume (dpv)
Bring up the Device Persistent Volume as a Helm chart (device-pv).

```shell
$> make dpv
```

Display the device persistent volume status

```shell
$> helm ls
```
NAME            REVISION        UPDATED                         STATUS          CHART                           APP VERSION     NAMESPACE
cord-kafka      1               Wed Nov 11 18:28:40 2020        DEPLOYED        kafka-0.13.3                    5.0.1           default
devices-pv      1               Wed Nov 11 20:47:46 2020        DEPLOYED        local-directory-0.1.0-dev0                      default


Bring up the Device Manager Kubenetes Pod
```shell
$> make dm
```

After bring up the device manager pod, the command can be used to check the status of Device Manager Pod.

```text
$> make status | grep device-management
manager       device-management-64b45fd858-477fv       1/1     Running   0          4h25m   192.168.0.12   device-manager   <none>
```

## Unload the Device Persistent Volume
The following command unloads the device persistent volume helm chart.

```shell
$> make clean-dpv
```

## Unload the Device Manager Pod
The following command unloads the device manager pod.

```shell
$> make clean-dm
```

## Build and run the demotest
The demotest is a daemon that create the connection interface for accessing the device.

Building demotest, requires the GoLang and protoc to be install.

```shell
$> cd demo_test
$> make go-install
$> . ~/.bashrc
$> make prereq
```
Build and run demotest.

```shell
$> cd demo_test
$> make demotest
```

After building demotest, the daemon can be run in the foreground which it will listen for commands from the "dm" program.

```text
$> cd demo_test
$> ./demotest
2020/09/09 14:51:00 Configuration:
2020/09/09 14:51:00     Kafka: kafka_ip.sh
2020/09/09 14:51:00     Listen Address: :9999
INFO[09-09-2020 14:51:00] Launching server...
```

```text
$> cd demo_test
$> ./demotest -s -t kafka_topic
2020/09/09 14:51:00 Configuration:
2020/09/09 14:51:00     Kafka: kafka_ip.sh
2020/09/09 14:51:00     Listen Address: :9999
INFO[09-09-2020 14:51:00] Launching server...
INFO[09-09-2020 14:51:00] kafkaInit starting
INFO[09-09-2020 14:51:00] IP address of kafka-cord-0: 192.168.253.130:9092
INFO[09-09-2020 14:51:00] Starting topicListener for kafka_topic
```

## Test physical devices
The automation test needs two physical devices to perform the test cases that include getting device data and functionality.

### Automation Test
Test cases utilize the **dm** executable. The **dm** executable is provided in the functional_test/ sub-directory. The test results will save a tarball file and locates in the "results" directory. They can execute those test cases through Makefile

```shell
$> cd demo_test/functional_test
$> make test IP1=<ip of 1st device> PORT1=<RF port of 1st device> IP2=<ip of 2nd device> PORT2=<RF port of 2nd device>
```

```shell
$> cd demo_test/functional_test
$> make test IP1=<ip of 1st device> PORT1=<RF port of 1st device> IP2=<ip of 2nd device> PORT2=<RF port of 2nd device>
             USER1=<user of 1st device> PWD1=<password of 1st device> USER2=<user of 2nd device> PWD2=<password of 2nd device>
```

The test case could specific by the "TESTSDIR" option (for exmaple: tests/account_service)
```shell
$> cd demo_test/functional_test
$> make test IP1=<ip of 1st device> PORT1=<RF port of 1st device> IP2=<ip of 2nd device> PORT2=<RF port of 2nd device>
             USER1=<user of 1st device> PWD1=<password of 1st device> USER2=<user of 2nd device> PWD2=<password of 2nd device>
             TESTSDIR=<test case directory>
```
### Manual testing at command line
The 'dm' test tool needs to build at the command line the following by

```shell
$> cd demo_test/functional_test
$> make dm
```
Before running 'dm', 'demotest' should be launched first.
The user manual for 'dm' is available at 'demo_test/functional_test/README'

## Reset k8s environment
The following command will remove all pods and helm chart.

```shell
$> make reset-pods
```

# Using the Makefile on Windows WSL/Ubuntu

## Install WSL (Windows Subsystem for Linux)

-   Install Ubuntu 22.04 from Microsoft Store

-   Select "Ubuntu 22.04.1 LTS"

Once installed, two applications will appear on the Windows Start menu: "Ubuntu 22.04.1 LTS" and "Ubuntu for Windows".

## Open Ubuntu environment

From the Window startup screen, select "Ubuntu 22.04.1 LTS". If "Ubuntu for Windows" is selected, a screen will launch but the environment is not setup correctly (bash, etc).

## Create Development Environment 

### Install Tools

1.  Install git

	```
	$> sudo apt-get install git
	```

2.  Install make

	```
	$> sudo apt-get install make
	```

3.  Install go

	```
	$> sudo apt-get install golang-go
	```

4.  Install protobuf compiler

	```
	$> sudo apt-get install protobuf-compiler
	```

5.  Install protoc-gen-go

	```
	$> go install github.com/golang/protobuf/protoc-gen-go@latest
	```

6.  Get repository

	```
	$> cd ~/app/src
	$> git clone <gitfile path for Device Manager repository>
	```

## Build and run Device Manager

1. Launch the makefile to build the Device Manager binary

	```
	$> cd ~/app/src/<DeviceManager folder>
	$> make device-manager-binary
	```

	This creates the GoLang file (manager.pb.go) and the executable (main)


	```
	./app/src/proto/manager.pb.go
	./app/src/apps/main
	```

2. Execute Device Manager

	```
	$> cd ./src/apps
	$> ./main
	```

# Working with tools

## WSL Ubuntu environment

### Show Ubuntu file system in an explorer window

```
$> explorer.exe .
```

## Using apt

### To install

```
$> sudo apt install \<package-name\>
```

### To uninstall

```
$> sudo apt remove \<package-name\>
```

## Using apt-file

### Install

```
$> sudo apt install apt-file
$> sudo apt-file update
```

### To find package location

```
$> apt-file search protoc-go-gen
```

## Using Go (GoLang)

### Show all environment variables

```
$> go env
```
### Show a specific environment variable

```
$> go env \<variable\>
$> go env GOPATH
```
### Set an environment variable to a value

```
$> go env -w \<variable\>=\<value\>
$> go env -w GOPATH=\~/app
```

### Reset an environment variable\'s value

```
$> go env -u \<variable\>
```
### Standard Go environment variables

GoLang has three standard environment variables

- GOROOT specifies the location of the Go SDK (e.g. /usr/lib/go.1.18)
- GOPATH specifies the location of your workspace (e.g. \~/app)
- GOBIN specifies the location of GoLang executable (e.g. \~/app/bin)

