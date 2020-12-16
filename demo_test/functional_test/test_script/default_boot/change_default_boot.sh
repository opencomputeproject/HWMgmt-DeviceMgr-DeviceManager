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
countingTime=5
waitTime=60

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

checkBootType()
{
   bootType=$1
   [ "${bootType,,}" != "open" -a "${bootType,,}" != "diag" -a "${bootType,,}" != "embed" -a "${bootType,,}" != "install" -a "${bootType,,}" != "rescue" -a "${bootType,,}" != "uninstall" -a "${bootType,,}" != "update" -a "${bootType,,}" != "sonic" ] && return 0
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

getsystemboot() {
    ip=$1
    port=$2
    ./dm attach $ip:$port:120 2>&1 >/dev/null
    ./dm setsessionservice $ip:$port:"":true:500 2>&1 >/dev/null
    token=`./dm logindevice $ip:$port:admin:redfish|cut -d' ' -f4`
    ./dm getsystembootdata  $ip:$port:$token
    ./dm detach $ip:$port:$token 2>&1 >/dev/null
}

setdefaultboot() {
    ip=$1
    port=$2
    bootType=$3
    ./dm attach $ip:$port:120 2>&1 >/dev/null
    ./dm setsessionservice $ip:$port:"":true:500 2>&1 >/dev/null
    token=`./dm logindevice $ip:$port:admin:redfish|cut -d' ' -f4`
    ./dm setdefaultboot $ip:$port:$token:$bootType
    ./dm detach $ip:$port:$token 2>&1 >/dev/null
}

resetDevice() {
    ip=$1
    port=$2
    ./dm attach $ip:$port:120 2>&1 >/dev/null
    ./dm setsessionservice $ip:$port:"":true:500 2>&1 >/dev/null
    token=`./dm logindevice $ip:$port:admin:redfish|cut -d' ' -f4`
    ./dm resetdevicesystem $ip:$port:$token:GracefulRestart
    ./dm detach $ip:$port:$token 2>&1 >/dev/null
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
echo -n "list device boot options: "
getsystemboot $IPaddress $port
read -p "Please input default boot option (open/diag/embed/install/rescue/update/sonic): " bootType
checkBootType $bootType && echo "Please check the boot option" && exit 0
setdefaultboot $IPaddress $port $bootType
echo "Send to device the default boot successfully"
read -p "ready for rebooting device: (y or n): " yesOrNo
[ "${yesOrNo,,}" != "y" -a "${yesOrNo,,}" != "n" ] && echo "Please check the input (y or n)!" && exit 0
[ "${yesOrNo,,}" == "n" ] && exit 0
resetDevice $IPaddress $port

counting=0
while :
do
    if [[ "$counting" -ge "$countingTime" ]]; then
        echo "excceed maximum waiting time $((countingTime*waitTime)) seconds!!, exiting procedure ..."
        exitProcess
    fi
    counting=$((counting+1))
    echo -n "Waiting $waitTime seconds for device ready : " && delayTime $waitTime && echo
    ./dm setsessionservice $IPaddress:$port:"":true:300 2>&1 > /dev/null
    checkDevice $IPaddress $port
    if [ "$?" == "1" ]; then
        echo "Now, The device is ready to use !"
        break
    fi
done
exitProcess
