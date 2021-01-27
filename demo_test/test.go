/* Edgecore DeviceManager
 * Copyright 2020-2021 Edgecore Networks, Inc.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"

	importer "device-management/demo_test/proto"

	"github.com/Shopify/sarama"
	logrus "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var EVENTS_MAP = map[string]string{
	"add":    "ResourceAdded",
	"rm":     "ResourceRemoved",
	"alert":  "Alert",
	"update": "ResourceUpdated"}

var BOOTS_MAP = map[string]string{
	"open":      "Open Network Linux",
	"diag":      "ONIE:diag",
	"embed":     "ONIE:embed",
	"install":   "ONIE:install",
	"rescue":    "ONIE:rescue",
	"uninstall": "ONIE:uninstall",
	"update":    "ONIE:update",
	"sonic":     "SONiC-OS"}

var importerTopic = "importer"
var DataConsumer sarama.Consumer

var cc importer.DeviceManagementClient
var ctx context.Context
var conn *grpc.ClientConn

func GetCurrentDevices() (error, []string) {
	logrus.Info("Testing GetCurrentDevices")
	empty := new(importer.Empty)
	var ret_msg *importer.DeviceListByIp
	ret_msg, err := cc.GetCurrentDevices(ctx, empty)
	if err != nil {
		return err, nil
	} else {
		return err, ret_msg.IpAddress
	}
}

func getRealSizeOf(v interface{}) (int, error) {
	b := new(bytes.Buffer)
	if err := gob.NewEncoder(b).Encode(v); err != nil {
		return 0, err
	}
	return b.Len(), nil
}

func init() {
	Formatter := new(logrus.TextFormatter)
	Formatter.TimestampFormat = "02-01-2006 15:04:05"
	Formatter.FullTimestamp = true
	logrus.SetFormatter(Formatter)
}

func topicListener(topic *string, master sarama.Consumer) {
	logrus.Info("Starting topicListener for ", *topic)
	consumer, err := master.ConsumePartition(*topic, 0, sarama.OffsetOldest)
	if err != nil {
		logrus.Errorf("topicListener panic, topic=[%s]: %s", *topic, err.Error())
		os.Exit(1)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	doneCh := make(chan struct{})
	go func() {
		for {
			select {
			case err := <-consumer.Errors():
				logrus.Errorf("Consumer error: %s", err.Err)
			case msg := <-consumer.Messages():
				logrus.Infof("Got message on topic=[%s]: %s", *topic, string(msg.Value))
			case <-signals:
				logrus.Warn("Interrupt is detected")
				os.Exit(1)
			}
		}
	}()
	<-doneCh
}

func kafkainit() {
	var kafkaIP string
	if GlobalConfig.Kafka == "kafka_ip.sh" {
		cmd := exec.Command("/bin/sh", "kafka_ip.sh")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			logrus.Info(err)
			os.Exit(1)
		}
		kafkaIP = out.String()
		kafkaIP = strings.TrimSuffix(kafkaIP, "\n")
		kafkaIP = kafkaIP + ":9092"
		logrus.Info("IP address of kafka-cord-0: ", kafkaIP)
	} else {
		kafkaIP = GlobalConfig.Kafka
	}

	config := sarama.NewConfig()
	config.Consumer.Return.Errors = true
	master, err := sarama.NewConsumer([]string{kafkaIP}, config)
	if err != nil {
		panic(err)
	}
	DataConsumer = master

	go topicListener(&importerTopic, master)
}

func main() {
	ParseCommandLine()
	ProcessGlobalOptions()
	ShowGlobalOptions()

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	logrus.Info("Launching server...")
	logrus.Info("kafkaInit starting")
	kafkainit()

	ln, err := net.Listen("tcp", GlobalConfig.Local)
	if err != nil {
		fmt.Println("could not listen")
		logrus.Fatalf("did not listen: %v", err)
	}
	defer ln.Close()

	conn, err = grpc.Dial(GlobalConfig.Importer, grpc.WithInsecure())
	if err != nil {
		logrus.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	cc = importer.NewDeviceManagementClient(conn)
	ctx = context.Background()

	loop := true

	for loop {
		connS, err := ln.Accept()
		if err != nil {
			logrus.Fatalf("Accept error: %v", err)
		}
		cmdstr, _ := bufio.NewReader(connS).ReadString('\n')
		cmdstr = strings.TrimSuffix(cmdstr, "\n")
		s := strings.Split(cmdstr, " ")
		newmessage := ""
		cmd := string(s[0])

		switch cmd {
		case "attach":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			var devicelist importer.DeviceList
			var ipattached []string
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 3 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceinfo := new(importer.DeviceInfo)
				deviceinfo.IpAddress = info[0] + ":" + info[1]
				freq, err := strconv.ParseUint(info[2], 10, 32)
				if err != nil {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceinfo.Frequency = uint32(freq)
				devicelist.Device = append(devicelist.Device, deviceinfo)
				ipattached = append(ipattached, deviceinfo.IpAddress)
			}
			if len(devicelist.Device) == 0 {
				break
			}
			_, err := cc.SendDeviceList(ctx, &devicelist)
			if err != nil {
				errStatus, _ := status.FromError(err)
				newmessage = newmessage + errStatus.Message()
				logrus.Errorf("attach error - status code %v message %v", errStatus.Code(), errStatus.Message())
			} else {
				ips := strings.Join(ipattached, " ")
				newmessage = newmessage + ips + " attached"
			}
		case "detach":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command " + cmdstr
				break
			}
			device := new(importer.Device)
			args := strings.Split(s[1], ":")
			if len(args) != 3 {
				newmessage = newmessage + "invalid command " + s[1]
				break
			}
			device.IpAddress = args[0] + ":" + args[1]
			device.UserToken = args[2]
			_, err := cc.DeleteDeviceList(ctx, device)
			if err != nil {
				errStatus, _ := status.FromError(err)
				newmessage = newmessage + errStatus.Message()
				logrus.Errorf("detach error - status code %v message %v", errStatus.Code(), errStatus.Message())
			} else {
				newmessage = newmessage + device.IpAddress + " detached"
			}
		case "period":
			if len(s) != 2 {
				newmessage = newmessage + "invalid command " + cmdstr
				break
			}
			args := strings.Split(s[1], ":")
			if len(args) != 4 {
				newmessage = newmessage + "invalid command " + s[1]
				break
			}
			ip := args[0] + ":" + args[1]
			token := args[2]
			pv := args[3]
			u, err := strconv.ParseUint(pv, 10, 64)
			if err != nil {
				logrus.Error("ParseUint error!!")
			} else {
				freqinfo := new(importer.FreqInfo)
				freqinfo.Frequency = uint32(u)
				freqinfo.IpAddress = ip
				freqinfo.UserToken = token
				_, err := cc.SetFrequency(ctx, freqinfo)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("period error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage
				}
			}
		case "QUIT":
			loop = false
			newmessage = "QUIT"
		case "showdevices":
			cmd_size := len(s)
			logrus.Infof("cmd is : %s cmd_size: %d", cmd, cmd_size)
			if cmd_size > 2 || cmd_size < 0 {
				logrus.Error("showdevices error !!")
				newmessage = "showdevices error !!"
			} else {
				err, currentlist := GetCurrentDevices()

				if err != nil {
					errStatus, _ := status.FromError(err)
					logrus.Errorf("GetCurrentDevice error: %s Status code: %d", errStatus.Message(), errStatus.Code())
					newmessage = errStatus.Message()
					logrus.Info("showdevices error!!")
				} else {
					logrus.Info("showdevices ", currentlist)
					newmessage = strings.Join(currentlist[:], " ")
				}
			}
		case "createaccount":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 6 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.UserToken = info[2]
				deviceAccount.ActUsername = info[3]
				deviceAccount.ActPassword = info[4]
				deviceAccount.Privilege = info[5]
				_, err := cc.CreateDeviceAccount(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("create user account error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceAccount.ActUsername + " created"
				}
			}
		case "deleteaccount":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 4 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.UserToken = info[2]
				deviceAccount.ActUsername = info[3]
				_, err := cc.RemoveDeviceAccount(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("delete user account error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceAccount.ActUsername + " deleted"
				}
			}
		case "changeuserpassword":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 5 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.UserToken = info[2]
				deviceAccount.ActUsername = info[3]
				deviceAccount.ActPassword = info[4]
				_, err := cc.ChangeDeviceUserPassword(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("change user password error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceAccount.IpAddress + " changed"
				}
			}
		case "logindevice":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 4 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.ActUsername = info[2]
				deviceAccount.ActPassword = info[3]
				ret_msg, err := cc.LoginDevice(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("login device error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					logrus.Info("logindevice token ", ret_msg.Httptoken)
					newmessage = newmessage + deviceAccount.IpAddress + " token : " + ret_msg.Httptoken + " logined"
				}
			}
		case "logoutdevice":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 4 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.UserToken = info[2]
				deviceAccount.ActUsername = info[3]
				_, err := cc.LogoutDevice(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("logout device error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceAccount.ActUsername + " logouted"
				}
			}
		case "startquerydevice":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 3 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.UserToken = info[2]
				_, err := cc.StartQueryDeviceData(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("logout device error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceAccount.IpAddress + " started"
				}
			}
		case "stopquerydevice":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 3 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.UserToken = info[2]
				_, err := cc.StopQueryDeviceData(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("logout device error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceAccount.IpAddress + " stopped"
				}
			}
		case "addpollingrfapi":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 4 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				rfList := new(importer.PollingRfAPI)
				rfList.IpAddress = info[0] + ":" + info[1]
				rfList.UserToken = info[2]
				rfList.RfAPI = info[3]
				_, err := cc.AddPollingRfAPI(ctx, rfList)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("adding polling Redfish API error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + " added"
				}
			}
		case "removepollingrfapi":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 4 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				rfList := new(importer.PollingRfAPI)
				rfList.IpAddress = info[0] + ":" + info[1]
				rfList.UserToken = info[2]
				rfList.RfAPI = info[3]
				_, err := cc.RemovePollingRfAPI(ctx, rfList)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("removing polling Redfish API error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + " removed"
				}
			}
		case "getpollingrflist":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 3 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				rfList := new(importer.PollingRfAPI)
				rfList.IpAddress = info[0] + ":" + info[1]
				rfList.UserToken = info[2]
				ret_msg, err := cc.GetRfAPIList(ctx, rfList)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("list polling Redfish API error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					logrus.Info(ret_msg.RfAPIList[:])
					sort.Strings(ret_msg.RfAPIList[:])
					s := fmt.Sprint(ret_msg.RfAPIList[:])
					newmessage = newmessage + "Polling Redfish API list : " + s
				}
			}
		case "deviceaccountslist":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 3 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.UserToken = info[2]
				deviceAccountList, err := cc.ListDeviceAccounts(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("list device accounts error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					logrus.Info(deviceAccountList)
					s := fmt.Sprint(deviceAccountList)
					newmessage = newmessage + "accounts list : " + s
				}
			}
		case "setsessionservice":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 5 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceAccount := new(importer.DeviceAccount)
				deviceAccount.IpAddress = info[0] + ":" + info[1]
				deviceAccount.UserToken = info[2]
				deviceAccount.SessionEnabled, _ = strconv.ParseBool(info[3])
				deviceAccount.SessionTimeout, _ = strconv.ParseUint(info[4], 10, 64)
				_, err := cc.SetSessionService(ctx, deviceAccount)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("set seesion service error - status code %v. %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceAccount.IpAddress + " set ok!"
				}
			}
		case "setlogservice":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 4 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceLogService := new(importer.LogService)
				deviceLogService.IpAddress = info[0] + ":" + info[1]
				deviceLogService.UserToken = info[2]
				deviceLogService.LogServiceEnabled, _ = strconv.ParseBool(info[3])
				_, err := cc.EnableLogServiceState(ctx, deviceLogService)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("set log service state error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceLogService.IpAddress + " set ok!"
				}
			}
		case "resetlogdata":
			if len(s) < 2 {
				newmessage = newmessage + "invalid command length" + cmdstr
				break
			}
			for _, devinfo := range s[1:] {
				info := strings.Split(devinfo, ":")
				if len(info) != 3 {
					newmessage = newmessage + "invalid command " + devinfo
					continue
				}
				deviceLogService := new(importer.LogService)
				deviceLogService.IpAddress = info[0] + ":" + info[1]
				deviceLogService.UserToken = info[2]
				_, err := cc.ResetDeviceLogData(ctx, deviceLogService)
				if err != nil {
					errStatus, _ := status.FromError(err)
					newmessage = newmessage + errStatus.Message()
					logrus.Errorf("reset log data error - status code %v message %v", errStatus.Code(), errStatus.Message())
				} else {
					newmessage = newmessage + deviceLogService.IpAddress + " set ok!"
				}
			}
		case "getdevicelogdata":
			if len(s) != 2 {
				newmessage = newmessage + "invalid command " + cmdstr
				break
			}
			args := strings.Split(s[1], ":")
			if len(args) < 3 {
				newmessage = newmessage + "invalid command " + args[0]
				break
			}
			deviceLogService := new(importer.LogService)
			deviceLogService.IpAddress = args[0] + ":" + args[1]
			deviceLogService.UserToken = args[2]
			ret_msg, err := cc.GetDeviceLogData(ctx, deviceLogService)
			if err != nil {
				errStatus, _ := status.FromError(err)
				newmessage = errStatus.Message()
				logrus.Errorf("get device log data error - status code %v message %v", errStatus.Code(), errStatus.Message())
			} else {
				logrus.Info("getdevicelogdata ", ret_msg.LogData)
				sort.Strings(ret_msg.LogData[:])
				newmessage = strings.Join(ret_msg.LogData[:], " ")
			}
		case "getdevicetemperaturedata":
			if len(s) != 2 {
				newmessage = newmessage + "invalid command " + cmdstr
				break
			}
			args := strings.Split(s[1], ":")
			if len(args) < 3 {
				newmessage = newmessage + "invalid command " + args[0]
				break
			}
			deviceTemperature := new(importer.DeviceTemperature)
			deviceTemperature.IpAddress = args[0] + ":" + args[1]
			deviceTemperature.UserToken = args[2]
			ret_msg, err := cc.GetDeviceTemperatures(ctx, deviceTemperature)
			if err != nil {
				errStatus, _ := status.FromError(err)
				newmessage = errStatus.Message()
				logrus.Errorf("get device temperature data error - status code %v message %v", errStatus.Code(), errStatus.Message())
			} else {
				logrus.Info("getdevicetemeraturedata ", ret_msg.TempData)
				sort.Strings(ret_msg.TempData[:])
				newmessage = strings.Join(ret_msg.TempData[:], " ")
			}
		case "getdevicedata":
			if len(s) != 2 {
				newmessage = newmessage + "invalid command " + cmdstr
				break
			}
			args := strings.Split(s[1], ":")
			if len(args) < 3 {
				newmessage = newmessage + "invalid command " + args[0]
				break
			}
			currentdeviceinfo := new(importer.Device)
			deviceaccountinfo := new(importer.DeviceAccount)
			currentdeviceinfo.IpAddress = args[0] + ":" + args[1]
			deviceaccountinfo.UserToken = args[2]
			currentdeviceinfo.RedfishAPI = args[3]
			currentdeviceinfo.DeviceAccount = deviceaccountinfo
			ret_msg, err := cc.GetDeviceData(ctx, currentdeviceinfo)
			if err != nil {
				errStatus, _ := status.FromError(err)
				newmessage = errStatus.Message()
				logrus.Errorf("get device data error - status code %v message %v", errStatus.Code(), errStatus.Message())
			} else {
				logrus.Info("getdevicedata ", ret_msg.DeviceData)
				sort.Strings(ret_msg.DeviceData[:])
				newmessage = strings.Join(ret_msg.DeviceData[:], " ")
			}
		case "deviceaccess":
			if len(s) != 2 {
				newmessage = newmessage + "1 invalid command " + cmdstr
				break
			}
			args := strings.Split(s[1], ":")
			if len(args) != 5 && len(args) != 6 {
				newmessage = newmessage + "2  invalid command " + args[0]
				break
			}
			currentdeviceinfo := new(importer.Device)
			deviceaccountinfo := new(importer.DeviceAccount)
			devicehttpinfo := new(importer.HttpInfo)
			httppostdata := new(importer.HttpPostData)
			httppatchdata := new(importer.HttpPatchData)
			currentdeviceinfo.IpAddress = args[0] + ":" + args[1]
			deviceaccountinfo.UserToken = args[2]
			devicehttpinfo.HttpMethod = args[3]
			currentdeviceinfo.RedfishAPI = args[4]
			currentdeviceinfo.DeviceAccount = deviceaccountinfo
			currentdeviceinfo.HttpInfo = devicehttpinfo
			if len(devicehttpinfo.HttpMethod) != 0 {
				switch devicehttpinfo.HttpMethod {
				case "POST":
					postData := map[string]string{}
					postData["UserName"] = strings.Split(args[5], "/")[0]
					postData["Password"] = strings.Split(args[5], "/")[1]
					pdata := importer.HttpPostData{PostData: postData}
					httppostdata.PostData = pdata.PostData
					devicehttpinfo.HttpPostData = httppostdata
					currentdeviceinfo.HttpInfo = devicehttpinfo
				case "DELETE":
					if args[5] == "" {
						newmessage = newmessage + "It needs 6 arguments separating by ':'" + args[0]
						break
					}
					devicehttpinfo.HttpDeleteData = args[5]
					currentdeviceinfo.HttpInfo = devicehttpinfo
				case "PATCH":
					if args[5] == "" {
						newmessage = newmessage + "It needs 6 arguments separating by ':'" + args[0]
						break
					}
					patchData := map[string]string{}
					patchData["Password"] = args[5]
					pdata := importer.HttpPatchData{PatchData: patchData}
					httppatchdata.PatchData = pdata.PatchData
					devicehttpinfo.HttpPatchData = httppatchdata
					currentdeviceinfo.HttpInfo = devicehttpinfo
				}
			}
			ret_msg, err := cc.GenericDeviceAccess(ctx, currentdeviceinfo)
			if err != nil {
				errStatus, _ := status.FromError(err)
				newmessage = errStatus.Message()
				logrus.Errorf("get device data error - status code %v message %v", errStatus.Code(), errStatus.Message())
			} else {
				newmessage = ret_msg.ResultData
			}
		case "listcommands":
			newmessage = newmessage + `The commands list :
attach - attach a device
	Usage: ./dm attach <ip address:port:period>
detach - detach a device
	Usage: ./dm detach <ip address:port:token>
period - a period of quering device data
	Usage: ./dm period <ip address:port:token:period>
showdevices - show registered device
	Usage: ./dm showdevices <none>
createaccount - create an account
	Usage: ./dm createaccount <ip address:port:token:username:password:privilege>
deleteaccount - delete an account
	Usage: ./dm deleteaccount <ip address:port:token:username>
changeuserpassword - change user password
	Usage: ./dm changeuserpassword <ip address:port:token:username:new passowrd>
logindevice - login to device
	Usage: ./dm logindevice <ip address:port:username:password>
logoutdevice - logout the device
	Usage: ./dm logoutdevice <ip address:port:token:username>
startquerydevice - start to query device
	Usage: ./dm startquerydevice <ip address:port:token>
stopquerydevice - stop to query device
	Usage: ./dm stopquerydevice <ip address:port:token>
deviceaccountslist - show device accounts
	Usage: ./dm deviceaccountslist <ip address:port:token>
setsessionservice - configure device authoriation
	Usage: ./dm setsessionservice <ip address:port:token:<true or false>:session timeout>
addpollingrfapi - add Redfish API to poll device data periodically
	Usage: ./dm addpollingrfapi <ip address:port:token:Redfish API>
removepollingrfapi - remove Redfish API from polling device data periodically
	Usage: ./dm removepollingrfapi <ip address:port:token:Redfish API>
getpollingrflist - show added Redfish API to poll device data periodically
	Usage: ./dm getpollingrflist <ip address:port:token>
setlogservice - enable/disable log service to device
	Usage: ./dm setlogservice <ip address:port:token:<true or false>>
resetlogdata - reset all log data to device
	Usage: ./dm resetlogdata <ip address:port:token>
getdevicelogdata - get all log data to device (maximum data count: 1000)
	Usage: ./dm getdevicelogdata <ip address:port:token>
getdevicetemperaturedata - get device tempertures infomation
	Usage: ./dm getdevicetemperaturedata <ip address:port:token>
getdevicedata - get device data from cache
	Usage: ./dm getdevicedata <ip address:port:token:Redfish API>
deviceaccess - access device data by Redfish API
	Usage: ./dm deviceaccess <ip address:port:token:HTTP method:Redfish API:HTTP DELETE/PATCH data>
`
		default:
			newmessage = newmessage + "3 invalid command " + cmdstr
		}
		// send string back to client
		n, err := connS.Write([]byte(newmessage + "\n" + ";"))
		if err != nil {
			logrus.Errorf("err writing to client:%s, n:%d", err, n)
			return
		}
	}
}
