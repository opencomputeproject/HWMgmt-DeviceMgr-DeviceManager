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

# Device Manager functionality
Device Manager retrieves and collects information from devices (Redfish compliant) by using **Redfish** API.
It uses ODIM's services to present data on northbound API.

# Hardware requirements
The Device Manager supports running the *Ubuntu Desktop 18.04 version*. For a single node deployment minimum requirement are
- CPU 8 cores,
- RAM 8GB,
- Storage of at least 40GB.

# Prerequisites
Before building Device Manager, the following steps are required:
- Go 1.17.10 installed,
  - To install Go and to download necessary packages together with libraries for building Device Manager, run:
  ```shell
  $ make go-install
  $ make prereq
  $ source ~/.bashrc
  ```
- Docker 20.10.18 (minimum version) installed,
- Certificates delivered or generated and placed into (project root)/build/certs (create this folder if necessary) (scripts for generation can be found [here](https://github.com/ODIM-Project/ODIM/tree/main/build/cert_generator)),
- Config changes to fit your needs(insert your own passwords in configs below (passwords can be different between configs) - use SHA3-512 hash and encode it with base64):
  - **Device Manager**
    - (project root)/svc-device-manager/config/config.yml
      - Basic Authentication -> Password
  - **ODIM services**
    - (project root)/lib-utilities/config/odimra_config.json
  - **Redis**
    - (project root)/build/redis/redis.conf
    - (project root)/build/redis/createSchema.sh
      - Line 4 -> "Password":"your_password_here"
  - **Etcd**
    - (project root)/build/etcd/etcd.yml

## Install Device Manager using single command
Use this command to install and run Device Manager together with ODIM services, Redis and Etcd as Docker containers.

```shell
$ make all
```

Once that make is complete, the Redfish interface will be available at 127.0.0.1:45000. The port number is specified by the **odimra_config.json** file, property **APIGatewayConf.Port**. The Redfish interface is used to create a connection to Device Manager.

## Register Device Manager
After installation, you have to register Device Manager to ODIM. This is done by using Aggregation Sources.
First, we need to know ID of Connection Method, which is of variant DM_v1.0.0. To do so, perform HTTP `GET`
on the following URI `https://{device-manager_host}:{port}/redfish/v1/AggregationService/ConnectionMethods`, 
providing `{user}:{password}` (your chosen username and password).
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

Next, perform HTTP `POST` on the URI: `https://{device-manager_host}:{port}/redfish/v1/AggregationService/AggregationSources`
with the following body (remember to replace ConnectionMethod with one that was found in previous request):

```shell
curl --location -X POST -k -u '{user}:{password}' 'https://127.0.0.1:45000/redfish/v1/AggregationService/AggregationSources' \
--header 'Content-Type: application/json' \
--data-raw '{
"HostName": "device-manager:45003",
"UserName": "admin",
"Password": "your_password",
"Links": {
"ConnectionMethod": {
"@odata.id": "/redfish/v1/AggregationService/ConnectionMethods/3326bd25-c230-4083-95d7-a51b7af5bec3"
}
}
}' |jq
```
After sending the request, Redfish task is created and a link to the task monitor associated with it is returned.

To add a BMC as an Aggregation source, firstly certificates must be imported in BMC server. Then, you can send another HTTP `POST` on the
URI: `https://{device-manager_host}:{port}/redfish/v1/AggregationService/AggregationSources` with the following body:
```shell
curl --location -X POST -k -u '{user}:{password}' 'https://127.0.0.1:45000/redfish/v1/AggregationService/AggregationSources' \
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

When tasks are finished, the following `GET` send on `https://{device-manager_host}:{port}/redfish/v1/AggregationService/ConnectionMethods/{ConnectionMethodID}` will show two previously added Aggregation sources.

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