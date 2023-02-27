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

Device Manager gets the device details from devices and periodically collects data using REDFISH RESTful APIS based on HTTP.
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
such as *CPU 2 cores/Memory 4GB and SSD driver 40GB*. The host system need to install necessary packages (ex: git, curl and docker)

# Prerequisites
Before building Device Manager, the following steps are required:
- Go 1.17.10 
  - To install Go and to download necessary packages together with libraries for building Device Manager, run:
  ```shell
  $ make go-install
  $ make prereq
  $ source ~/.bashrc
  ```
- certificates must be generated (scripts to generate certificates are provided at https://github.com/ODIM-Project/ODIM/tree/main/build/cert_generator)
- cert files must be placed in /etc/deviceManager/certs folder.

## Install Device Manager and ODIM using single command
This single command will install and run Device Manager as well as ODIM with all necessary packages.

```shell
$ make all
```
# Installation step by step
Skip this section, if you used make all to build and run Device Manager as well as ODIM.


## Build proto file
Build proto files for Device Manager.
```shell
$ make generate-proto
```

## Building Device Manager
Build and run Device Manager.
```shell
$ make buildDeviceMgr
```

## Install ODIM's services with single command
To install ODIM run following command:

```shell
$ make buildAndRunODIM
```

## Building ODIM step by step
Skip this section, if you used make buildAndRunODIM to build and run ODIM.

### Prerequisites
To build ODIM's services, the following software is required:

- Redis 6.2.5 (https://redis.io/download/)
    - Download config for Redis
    - Configure and start Redis for both InMemory and OnDisk DB
  ```shell
    $ redis-server /src/config/redis.conf --protected-mode no
    $ redis-server /src/config/redis.conf --protected-mode no --port 6380
  ```
    - Fill Redis with data
  ```shell
  $ build/createSchema.sh
  ```
- etcd (https://etcd.io/docs/v3.4/install/)
  - Start etcd using config file
  ```shell
  $ etcd --config-file /src/config/etcd.conf
  ```
### Generate proto files for ODIM's services
```shell
$ build/buildProtoForODIMServices.sh
```

### Build ODIM's services

```shell
$ build/buildODIMServices.sh
```

### Run ODIM's services
- Run services with following program arguments: `--registry_address=127.0.0.1:2379 --server_address=127.0.0.1:45102`
```shell
$ svc-account-session/svc-account-session --registry_address=127.0.0.1:2379 --server_address=127.0.0.1:45101
$ svc-aggregation/svc-aggregation --registry_address=127.0.0.1:2379 --server_address=127.0.0.1:45102
$ svc-api/svc-api --registry_address=127.0.0.1:2379 --server_address=127.0.0.1
$ svc-events/svc-events --registry_address=127.0.0.1:2379 --server_address=127.0.0.1:45103
$ svc-systems/svc-systems --registry_address=127.0.0.1:2379 --server_address=127.0.0.1:45104
$ svc-task/svc-task --registry_address=127.0.0.1:2379 --server_address=127.0.0.1:45105
```
or execute
```shell
$ build/runODIMServices.sh
```

## Register Device Manager in ODIM

To add Device Manager plugin, we need to add Aggregation Sources to ODIM.
First, we need to know ID of Connection Method, which is of variant DM_v1.0.0. To do so, perform HTTP `GET` on the following URI `https://{odim_host}:{port}/redfish/v1/AggregationService/ConnectionMethods`, 
providing `{user}:{password}` (default username is `admin` and default password is `Od!m12$4`).
Check each record, to find the proper Connection Method.

```shell
curl  -k -u  '{user}:{password}' https://127.0.0.1:45000/redfish/v1/AggregationService/ConnectionMethods/3326bd25-c230-4083-95d7-a51b7af5bec3 | jq
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
Dload  Upload   Total   Spent    Left  Speed
100   642    0   642    0     0   6356      0 --:--:-- --:--:-- --:--:--  6356
{
"@odata.type": "#ConnectionMethod.v1_0_0.ConnectionMethod",
"@odata.id": "/redfish/v1/AggregationService/ConnectionMethods/3326bd25-c230-4083-95d7-a51b7af5bec3",
"@odata.context": "/redfish/v1/$metadata#ConnectionMethod.v1_0_0.ConnectionMethod",
"Id": "3326bd25-c230-4083-95d7-a51b7af5bec3",
"Name": "Connection Method",
"ConnectionMethodType": "Redfish",
"ConnectionMethodVariant": "Compute:BasicAuth:DM_v1.0.0",
"Links": {
"AggregationSources": []
}
}
```

Next, perform HTTP `POST` on the URI: `https://{odim_host}:{port}/redfish/v1/AggregationService/AggregationSources` with the following body:

```shell
curl --location -X POST -k -u '{user}:{password}' 'https://odim.local.com:45000/redfish/v1/AggregationService/AggregationSources' \
--header 'Authorization: Basic YWRtaW46T2QhbTEyJDQ=' \
--header 'Content-Type: application/json' \
--data-raw '{
"HostName": "localhost:45003",
"UserName": "admin",
"Password": "D3v1ceMgr",
"Links": {
"ConnectionMethod": {
"@odata.id": "/redfish/v1/AggregationService/ConnectionMethods/3326bd25-c230-4083-95d7-a51b7af5bec3"
}
}
}' |jq
```
After sending the request, Redfish task is created and a link to the task monitor associated with it is returned.

To add a BMC as an Aggregation source, firstly certificates must be imported in BMC server. Then, you can send another HTTP `POST` on the URI: `https://{odim_host}:{port}/redfish/v1/AggregationService/AggregationSources` with the following body:
```shell
curl --location -X POST -k -u '{user}:{password}' 'https://odim.local.com:45000/redfish/v1/AggregationService/AggregationSources' \
--header 'Authorization: Basic YWRtaW46T2QhbTEyJDQ=' \
--header 'Content-Type: application/json' \
--data-raw '{
"HostName": "{BMC_address}",
"UserName": "{BMC_UserName}",
"Password": "{BMC_Password}",
"Links": {
"ConnectionMethod": {
"@odata.id": "/redfish/v1/AggregationService/ConnectionMethods/3326bd25-c230-4083-95d7-a51b7af5bec3"
}
}
}' |jq
```
After sending the request, Redfish task is created and a link to the task monitor associated with it is returned.

When tasks are finished, the following `GET` send on `https://{odim_host}:{port}/redfish/v1/AggregationService/ConnectionMethods/{ConnectionMethodID}` will show two previously added Aggregation sources.

```shell
curl  -k -u  '{user}:{password}' https://127.0.0.1:45000/redfish/v1/AggregationService/ConnectionMethods/3326bd25-c230-4083-95d7-a51b7af5bec3 | jq
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
Dload  Upload   Total   Spent    Left  Speed
100   642    0   642    0     0   6356      0 --:--:-- --:--:-- --:--:--  6356
{
"@odata.type": "#ConnectionMethod.v1_0_0.ConnectionMethod",
"@odata.id": "/redfish/v1/AggregationService/ConnectionMethods/3326bd25-c230-4083-95d7-a51b7af5bec3",
"@odata.context": "/redfish/v1/$metadata#ConnectionMethod.v1_0_0.ConnectionMethod",
"Id": "3326bd25-c230-4083-95d7-a51b7af5bec3",
"Name": "Connection Method",
"ConnectionMethodType": "Redfish",
"ConnectionMethodVariant": "Compute:BasicAuth:DM_v1.0.0",
"Links": {
"AggregationSources": [
{
"@odata.id": "/redfish/v1/AggregationService/AggregationSources/99999999-9999-9999-9999-999999999999"
},
{
"@odata.id": "/redfish/v1/AggregationService/AggregationSources/207c0230-ed7b-412c-968a-d604c03aea16.1"
}
]
}
}
```