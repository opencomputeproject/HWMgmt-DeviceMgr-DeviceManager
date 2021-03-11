#!/bin/sh
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

NAGIOS_VER=4.4.6
CUSTOMIZED_FOLDER_NAME=src
PWD=$(pwd)
echo "Input Device Manager server IP address:"
read DEVICE_MANGER_SERVER_IP
echo Testing DEVICE_MANGER_SERVER_IP: $DEVICE_MANGER_SERVER_IP ....
if CHK=`ping $DEVICE_MANGER_SERVER_IP -c 1|grep "100% packet loss" 2>&1`;then
    echo "Server $DEVICE_MANGER_SERVER_IP is not reachable"
    exit 1
fi

echo "Input Device IP address:"
read DEVICE_IP
echo Testing DEVICE_IP: $DEVICE_IP ....
if CHK=`ping $DEVICE_IP -c 1|grep "100% packet loss" 2>&1`;then
    echo "Device $DEVICE_IP is not reachable"
    exit 1
fi

sudo apt-get install build-essential unzip -y
sudo apt install autoconf bc gawk dc gcc libc6 wget unzip apache2 php libapache2-mod-php7.2 libgd-dev libmcrypt-dev make libssl-dev snmp libnet-snmp-perl gettext -y

if [ -f nagios-4.4.6.tar.gz ];then
    tar zxvf nagios-4.4.6.tar.gz
else
    echo "file nagios-4.4.6.tar.gz not found"
    exit 1
fi

cd nagios-${NAGIOS_VER}
if [ $? == 1 ];then
    echo "exit 1"
    exit 1
fi
# 1. Copy custimized cgi file for dashboard UI
if [ ! -f cgi/ec_status.c ];then
    cp -af ../${CUSTOMIZED_FOLDER_NAME}/cgi/ec_host_status.c cgi/
    cp -af ../${CUSTOMIZED_FOLDER_NAME}/cgi/Makefile cgi/
    cp -af ../${CUSTOMIZED_FOLDER_NAME}/cgi/Makefile.in cgi/
fi

cd ..
# 2. Copy icon file and php webpage for custimized UI
cp -af ${CUSTOMIZED_FOLDER_NAME}/html/images/* nagios-${NAGIOS_VER}/html/images/
cp -af ${CUSTOMIZED_FOLDER_NAME}/html/side.php nagios-${NAGIOS_VER}/html/
cp -af ${CUSTOMIZED_FOLDER_NAME}/html/ec_more_info.php nagios-${NAGIOS_VER}/html/

# 3. create user nagios and set permission 
if CHK=`id nagios 2>&1|grep "no such user"`;then
    cd nagios-${NAGIOS_VER}
    sudo ./configure --with-httpd-conf=/etc/apache2/sites-enabled
    sudo make install-groups-users
    echo sudo make install-groups-users
    sudo usermod -aG nagios www-data
    echo usermod -aG nagios www-data
    sudo usermod -aG sudo nagios
    echo usermod -aG sudo nagios
else
    cd nagios-${NAGIOS_VER}
    sudo ./configure --with-httpd-conf=/etc/apache2/sites-enabled
fi

# 4. make all & make install
sudo make all
sudo make install
sudo make install-daemoninit
sudo make install-commandmode
sudo make install-config
sudo make install-webconf
sudo a2enmod rewrite cgi
sudo systemctl restart apache2
echo sudo htpasswd -c /usr/local/nagios/etc/htpasswd.users nagiosadmin
sudo htpasswd -c /usr/local/nagios/etc/htpasswd.users nagiosadmin

#sudo apt install nagios-nrpe-server -y
sudo apt install nagios-plugins -y

cd ..
# 5. Append check command to objects/commands.cfg
sudo cp -af src/usr/local/nagios/etc/objects/commands.cfg /usr/local/nagios/etc/objects/commands.cfg
if ! CHK=`cat /usr/local/nagios/etc/objects/commands.cfg|grep ec_check_sn`;then
    sudo sh -c 'echo "
define command{
       command_name ec_check_sn
       command_line /usr/lib/nagios/plugins/grpc/proto/./grpc_client.py --dm-ip \$ARG1$:31085 --device-ip \$ARG2$:8888 --getchassisinfo
}
" >> /usr/local/nagios/etc/objects/commands.cfg'
fi

# 6. Copy nagios configuration file to nagios path

sudo cp -af src/usr/local/nagios/etc/nagios.cfg /usr/local/nagios/etc/
sudo cp -af src/usr/local/nagios/etc/resource.cfg /usr/local/nagios/etc/
sudo chown nagios.nagios /usr/local/nagios/etc/nagios.cfg /usr/local/nagios/etc/resource.cfg

# 7. Update python3 to the latest version. Install gRPC python package 
if ! CHK=`sudo python3 --version|grep "Python"|grep "3.8"`;then
    sudo apt-get install python3.8 -y
    sudo python3 -m pip install --upgrade pip
    sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 1
    sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 2
    sudo update-alternatives --config python3
fi
sudo apt-get install python3-pip -y
sudo pip3 install grpcio grpcio-tools
sudo pip3 install argparse
cd src/usr/lib/nagios/plugins/grpc/proto
pwd
sleep 5
sudo python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ./importer.proto
cd -
sudo cp -af src/usr/lib/nagios/plugins/grpc /usr/lib/nagios/plugins/
sudo chmod +x /usr/lib/nagios/plugins/grpc/proto/grpc_client.py

# 8. Install client configuation
sudo mkdir -p /usr/local/nagios/etc/servers/
sudo cp -af src/usr/local/nagios/etc/servers/client01.cfg /usr/local/nagios/etc/servers/
sudo sh -c "echo '
define service {
      host_name                       client01
      service_description             Serial Number
      check_command                   ec_check_sn!${DEVICE_MANGER_SERVER_IP}!${DEVICE_IP}
      max_check_attempts              5
      check_interval                  1
      retry_interval                  3
      check_period                    24x7
} 
' >> /usr/local/nagios/etc/servers/client01.cfg"

# Change the client config IP to Device IP 
sudo sed -i "s/10.5.1.201/${DEVICE_IP}/1" /usr/local/nagios/etc/servers/client01.cfg

# 9. Enable www-data privileges to execute python script by php
if ! CHK=`sudo cat /etc/sudoers|grep "www-data"`;then
    sudo chmod 755 /etc/sudoers
    sudo sed -i '$a %www-data ALL=(ALL) NOPASSWD: ALL' /etc/sudoers
    sudo chmod 440 /etc/sudoers
fi

# 10. start nagios service
sudo service nagios restart

