#!/usr/bin/python3
#  Edgecore DeviceManager
#  Copyright 2020-2021 Edgecore Networks, Inc.
#
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements. See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership. The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License. You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied. See the License for the
#  specific language governing permissions and limitations
#  under the License.

import grpc
import sys
import json
import argparse
import importer_pb2
import importer_pb2_grpc

debug_mode = False

def create_channel(dm_ip):
    channel = grpc.insecure_channel(dm_ip)
    stub = importer_pb2_grpc.device_managementStub(channel)
    return stub

def attch(dm_ip, device_ip):
    stub = create_channel(dm_ip)
    device_info = importer_pb2.DeviceInfo(ip_address=device_ip, frequency=120, detectDevice=True)
    #list = []
    #list.append(device_info)
    device_list = importer_pb2.DeviceList(device = [device_info])
    stub.SendDeviceList(device_list)

def enable_session(dm_ip, device_ip):
    stub = create_channel(dm_ip)
    #enable
    stub.SetSessionService(importer_pb2.DeviceAccount(IpAddress=device_ip, sessionEnabled=True ,sessionTimeout=6000))

def login_device(stub, dm_ip, device_ip):
    #login
    # new a DeviceAccount object name: device_account_login
    device_account_login = importer_pb2.DeviceAccount(IpAddress=device_ip, actUsername='admin', actPassword='redfish')
    response = stub.LoginDevice(device_account_login)
    if debug_mode:
        print("HTTP TOKEN: " + str(response.httptoken))
    return str(response.httptoken)

def start_query_device(dm_ip, device_ip):

    stub = create_channel(dm_ip)
    token = login_device(stub, dm_ip, device_ip)

    # new a DeviceAccount object name: device_account_ip_usertoken
    device_account_ip_usertoken = importer_pb2.DeviceAccount(IpAddress=device_ip, userToken=token)
    stub.StartQueryDeviceData(device_account_ip_usertoken)

def stop_query_device(dm_ip, device_ip):

    stub = create_channel(dm_ip)
    token = login_device(stub, dm_ip, device_ip)

    # new a DeviceAccount object name: device_account_ip_usertoken
    device_account_ip_usertoken = importer_pb2.DeviceAccount(IpAddress=device_ip, userToken=token)
    stub.StopQueryDeviceData(device_account_ip_usertoken)

def get_chassis_info(dm_ip, device_ip):
    stub = create_channel(dm_ip)
    token = login_device(stub, dm_ip, device_ip)

    # new a DeviceAccount object name: device_account_usertoken
    device_account_usertoken = importer_pb2.DeviceAccount(userToken=token)
    # new a Device object name: device
    device = importer_pb2.Device(IpAddress=device_ip, deviceAccount = device_account_usertoken, RedfishAPI='/redfish/v1/Chassis/1')
    response = stub.GetDeviceData(device)
    if debug_mode:
        print("DEVICE REDFISH API: " + str(response.deviceData[0]))

    x = str(response.deviceData[0])
    y = json.loads(x)
    #print("TimeStamp: " + y["DataTimestamp"])
    #print("Chassis-ID: " + y["@odata.id"])
    print(y["SerialNumber"])
    #print("PartNumber: " + y["PartNumber"])
    #print("Manufacturer: " + y["Manufacturer"])
    #print("Model: " + y["Model"])

def get_thermalsensor_info(dm_ip, device_ip):
    stub = create_channel(dm_ip)
    token = login_device(stub, dm_ip, device_ip)

    # new a DeviceAccount object name: device_account_usertoken
    device_account_usertoken = importer_pb2.DeviceAccount(userToken=token)
    # new a Device object name: device
    device = importer_pb2.Device(IpAddress=device_ip, deviceAccount = device_account_usertoken, RedfishAPI='/redfish/v1/Chassis/1/Thermal')
    response = stub.GetDeviceData(device)
    if debug_mode:
        print("DEVICE REDFISH API: " + str(response.deviceData[0]))

    x = str(response.deviceData[0])
    y = json.loads(x)
    #print("TimeStamp: " + y["DataTimestamp"])
    #print("Temperatures: ")
    temperatures = {}

    for temp in y["Temperatures"]:
        json_str = ""
        print("%s %s %s %s"%(temp["MemberId"], temp["PhysicalContext"],temp["Status"]["HealthRollup"],temp["ReadingCelsius"]))
        #print(temp["Name"])
        #print(temp["PhysicalContext"])
        #print(temp["Status"]["HealthRollup"])
        #print(temp["ReadingCelsius"])
def get_psu_power_info(dm_ip, device_ip):
    stub = create_channel(dm_ip)
    token = login_device(stub, dm_ip, device_ip)

    # new a DeviceAccount object name: device_account_usertoken
    device_account_usertoken = importer_pb2.DeviceAccount(userToken=token)
    # new a Device object name: device
    device = importer_pb2.Device(IpAddress=device_ip, deviceAccount = device_account_usertoken, RedfishAPI='/redfish/v1/Chassis/1/Power')
    response = stub.GetDeviceData(device)
    if debug_mode:
        print("DEVICE REDFISH API: " + str(response.deviceData[0]))
    x = str(response.deviceData[0])
    y = json.loads(x)
    for power in y["PowerControl"]:
        print("ID:%s Watts:%s Status:%s State:%s"%(power["MemberId"], power["PowerConsumedWatts"], power["Status"]["Health"], power["Status"]["State"]))
        #print(power["PowerConsumedWatts"])
        #print(power["Status"]["Health"])
        #print(power["Status"]["State"])

def detach(dm_ip, device_ip):
    stub = create_channel(dm_ip)
    token = login_device(stub, dm_ip, device_ip)
    device = importer_pb2.Device(IpAddress=device_ip, userToken=token)
    stub.DeleteDeviceList(device)

def cli():
    parser = argparse.ArgumentParser(
        description="To get device information from Device Manager by gRPC API")
    parser.add_argument("--dm-ip",
        help="Device Manager IP address [IP]:31085",
        metavar = "dm_ip",
        type=str,
        required=True)
    parser.add_argument("--device-ip",
        help="Device IP address [IP]:[8888|8889]",
        metavar = "device_ip",
        type=str,
        required=True)
    parser.add_argument("--attach",
    action = "store_true",
    help = "Attach device")

    parser.add_argument("--enablesession",
    action = "store_true",
    help = "Enable session")

    parser.add_argument("--logindevice",
    action = "store_true",
    help = "Login device")

    parser.add_argument("--startquerydevice",
    action = "store_true",
    help = "Enable device to start query log")

    parser.add_argument("--stopquerydevice",
    action = "store_true",
    help = "Disable device to start query log")

    parser.add_argument("--getchassisinfo",
    action = "store_true",
    help = "Get chassis information")

    parser.add_argument("--getthermalsensorinfo",
    action = "store_true",
    help = "Get thermal sensor info")

    parser.add_argument("--getpsupowerinfo",
    action = "store_true",
    help = "Get thermal sensor info")

    parser.add_argument("--detach",
    action = "store_true",
    help = "Detach device")

    parser.add_argument("--debug",
    action = "store_true",
    help = "Enable DEBUG")

    args = parser.parse_args()
    if args.debug:
        debug_mode = True
        print("device_manager_ip: %s"%args.dm_ip)
        print("device_ipdevice_ip: %s"%args.device_ip)
    else:
        debug_mode = False

    if args.attach:
        if debug_mode:
            print("attach: %s"%args.attach)
        attch(args.dm_ip, args.device_ip)
    elif args.enablesession:
        if debug_mode:
            print("enablesession: %s"%args.enablesession)
        enable_session(args.dm_ip, args.device_ip)
    elif args.logindevice:
        if debug_mode:
            print("enablesession: %s"%args.logindevice)
        stub = create_channel(args.dm_ip)
        login_device(stub, args.dm_ip, args.device_ip)
    elif args.startquerydevice:
        if debug_mode:
            print("startquerydevice: %s"%args.startquerydevice)
        start_query_device(args.dm_ip, args.device_ip)
    elif args.stopquerydevice:
        if debug_mode:
            print("stopquerydevice: %s"%args.stopquerydevice)
        stop_query_device(args.dm_ip, args.device_ip)
    elif args.getchassisinfo:
        if debug_mode:
            print("getchassisinfo: %s"%args.getchassisinfo)
        get_chassis_info(args.dm_ip, args.device_ip)
    elif args.getthermalsensorinfo:
        if debug_mode:
            print("getthermalsensorinfo: %s"%args.getthermalsensorinfo)
        get_thermalsensor_info(args.dm_ip, args.device_ip)
    elif args.getpsupowerinfo:
        if debug_mode:
            print("getpsupowerinfo: %s"%args.getpsupowerinfo)
        get_psu_power_info(args.dm_ip, args.device_ip)
    elif args.detach:
        if debug_mode:
            print("detach: %s"%args.detach)
        detach(args.dm_ip, args.device_ip)

if __name__ == '__main__':

    try:
        cli()
    except Exception as e:
        print(e)


