#!/bin/bash

# Edgecore DeviceManager
# Copyright 2020-2021 Edgecore Networks, Inc.
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

DIR=`pwd`
SoftwareUpdateRedfishAPI="/redfish/v1/UpdateService/FirmwareInventory"
countingTime=60
waitTime=20

checkIpAddress()
{
   [ "$1" == "0.0.0.0" ] && return 0
   if [[ "$1" =~ (([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([01]{,1}[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$ ]]; then
      return 1
   else
      return 0
   fi
}

checkPort()
{
   [ -z "${port//[0-9]}" ] && [ -n "$port" ] || return 0
   [[ "$port" -le 1023 ]] || [[ "$port" -ge 65535 ]] && return 0
   return 1
}

checkSoftwareType()
{
   softwareType=$1
   [ "${softwareType,,}" != "nos" -a "${softwareType,,}" != "mu" ] && return 0
   return 1
}

checkSoftwareDownloadURI()
{
   [ -z `echo ${uri,,} | grep 'http://\|https://'` ] && return 0
   return 1
}

delayTime()
{
   maxTime=$1
   counter=0
   while true; do
       [[ "$counter" -ge "$maxTime" ]] && return 0
       echo -n "."
       sleep 1
       counter=$((counter + 1))
   done
}

exitProcess()
{
    ip=$1
    port=$2
    token=$3
    ./dm detach $ip:$port:$token
    [ ! -z "`pidof demotest`" ] && pkill demotest
    exit 0
}

initialDevice()
{
    ip=$1
    port=$2
    ./dm attach $ip:$port:120
    ./dm setsessionservice $ip:$port:"":true:500
    token=`./dm logindevice $ip:$port:admin:redfish|cut -d' ' -f4`
    ./dm detach $ip:$port:$token
}

checkDevice()
{
    ip=$1
    port=$2
    (echo >/dev/tcp/$ip/$port) &>/dev/null && return 1 || return 0
}

[ ! -z "`pidof demotest`" ] && pkill demotest
cd ..
./demotest > ./demotest.log 2>&1 &
cd $DIR

read -p "Please input device IP address: " IPaddress
checkIpAddress $IPaddress && echo "Please check device IP address" && exit 0
read -p "Please input PSME listen port (1024~65534, ex: 8888 or 8889): " port
checkPort $port && echo "Please check PSME listen port" && exit 0
checkDevice $IPaddress $port && echo "The device network could not reachable" && exit 0
initialDevice $IPaddress $port 2>&1 > /dev/null
read -p "Please input software type (ex: MU or NOS): " updateType
checkSoftwareType $updateType && echo "Please select \"MU\" or \"NOS\"" && exit 0
read -p "Please input software download URI (ex: http://abc.com or https://abc.com): " uri
checkSoftwareDownloadURI $uri && echo "Please input \"http://\" or \"https://\"" && exit 0
echo "Send software download URI ($uri) to device successfully"

httpType=`echo $uri|awk -F":" '{print $1}'`
downloadIP=`echo $uri|awk -F":|/" '{print $4}'`
tmpUrl=`echo $uri|cut -d'/' -f2-` 
if [ ! -z "`echo $tmpUrl|grep :`" ]; then
    httpPort=`echo $tmpUrl|awk -F":|/" '{print $3}'`
    url=`echo $tmpUrl|cut -d'/' -f3-`
else
    httpPort=""
fi
url=`echo $tmpUrl|cut -d'/' -f3-`

# proceed to login device and perform software update
./dm attach $IPaddress:$port:120
./dm setsessionservice $IPaddress:$port:"":true:300
token=`./dm logindevice $IPaddress:$port:admin:redfish| cut -d' ' -f4`
result=`./dm devicesoftwareupdate $IPaddress:$port:$token:${updateType^^}:$httpType:$downloadIP:$httpPort:$url`
[ -z "`echo $result|grep \"set ok\"`" ] && echo $result && \
    echo "It failed to send the download software URI to the device" && exitProcess $IPaddress $port $token
delayTime 2 && echo
updateState=`./dm deviceaccess $IPaddress:$port:$token:GET:$SoftwareUpdateRedfishAPI/${updateType^^}:""| \
    awk -F'UpdateState\":' '{print $2}'|cut -d'"' -f2`
echo "Now, The device software update is \"$updateState\""

# Device Software/Firmware Update Status:
#+--------------+--------------------------------------------------------+
#| None         | The Device does not have any update process before     |
#+--------------+--------------------------------------------------------+
#| Downloading  | Firmware image is downloading                          |
#+--------------+--------------------------------------------------------+
#| InProcessing | Preparing update process                               |
#+--------------+--------------------------------------------------------+
#| Rebooting    | Reboot into ONIE to start update process               |
#+--------------+--------------------------------------------------------+
#| LastCompletedAt | The last success update time                        |
#+--------------+--------------------------------------------------------+
#| Failure      | The last time update result is failure                 |
#+--------------+--------------------------------------------------------+

counting=0
while :
do
    if [[ "$counting" -ge "$countingTime" ]]; then
        echo "excceed maximum waiting time $((countingTime*waitTime)) seconds!!, exiting procedure ..."
        exitProcess $IPaddress $port $token
    fi
    counting=$((counting+1))
    echo -n "Waiting $waitTime seconds for device software update : " && delayTime $waitTime && echo
    ./dm setsessionservice $IPaddress:$port:"":true:300 2>&1 > /dev/null
    token=`./dm logindevice $IPaddress:$port:admin:redfish| cut -d' ' -f4`
    updateState=`./dm deviceaccess $IPaddress:$port:$token:GET:$SoftwareUpdateRedfishAPI/${updateType^^}:""| \
        awk -F'UpdateState\":' '{print $2}'|cut -d'"' -f2`
    if [ ! -z "$updateState" ]; then
        echo "Now, The device software update is \"$updateState\""
        if [ ! -z "`echo $updateState|grep LastCompletedAt`" ]; then
            echo "Update device software successfully ..."
            echo "Device Update Time: `echo $updateState|cut -d' ' -f2`"
            break
        elif [ $updateState = "Failure" ]; then
            echo "Now, The device software update is \"$updateState\""
            echo "Abort, exiting softeware update procedure ..."
            break
        fi
    fi
done
exitProcess $IPaddress $port $token

