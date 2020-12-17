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
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"device-management/proto"
	"github.com/Shopify/sarama"
	empty "github.com/golang/protobuf/ptypes/empty"

	logrus "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type scheduler struct {
	getdata    *time.Ticker
	quit       chan bool
	getdataend chan bool
}

type loginInfo struct {
	username string
	password string
	token    string
}

type device struct {
	Subscriptions      map[string]string `json:"subscriptions"`
	Freq               uint32            `json:"frequency"`
	Datacollector      scheduler         `json:"-"`
	Freqchan           chan uint32       `json:"-"`
	Eventtypes         []string          `json:"eventtypes"`
	Datafile           *os.File          `json:"-"`
	DeviceDatafile     *os.File          `json:"-"`
	UserLoginInfo      map[string]string `json:"userlogin"`
	QueryState         bool              `json:"-"`
	QueryUser          string            `json:"-"`
	DeviceLockFile     sync.Mutex        `json:"-"`
	DeviceDataLockFile sync.Mutex        `json:"-"`
	RfAPIList          []string          `json:"redfishAPIList"`
	Model              string            `json:"model"`
}

type Server struct {
	devicemap    map[string]*device
	gRPCserver   *grpc.Server
	dataproducer sarama.AsyncProducer
	httpclient   *http.Client
}

func (s *Server) ClearCurrentEventList(c context.Context, device *importer.Device) (*empty.Empty, error) {
	logrus.Info("Received ClearCurrentEventList")
	var token, ipAddress string
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = device.IpAddress
	account := device.DeviceAccount
	if account == nil {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	token = account.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	removeEvents, statusCode, err := s.checkSubscription(ipAddress, token)
	if err != nil || statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	statusCode, err = s.removeSubscription(ipAddress, token, removeEvents)
	if err != nil || statusCode != http.StatusNoContent {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetCurrentEventList(c context.Context, device *importer.Device) (*importer.EventList, error) {
	logrus.Info("Received GetCurrentEventList")
	var token, ipAddress string
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = device.IpAddress
	account := device.DeviceAccount
	if account == nil {
		return nil, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	token = account.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": device.IpAddress}).Info("Device ip " + device.IpAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	events, statusCode, err := s.checkSubscription(ipAddress, token)
	if err != nil || statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	currentevents := new(importer.EventList)
	if events != nil {
		for _, event := range events {
			currentevents.Events = append(currentevents.Events, event)
		}
	}
	return currentevents, nil
}

func (s *Server) GetEventList(c context.Context, device *importer.Device) (*importer.EventList, error) {
	logrus.Info("Received GetEventList")
	var token, ipAddress string
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = device.IpAddress
	account := device.DeviceAccount
	if account == nil {
		return nil, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	token = account.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	events, statusCode, err := s.getEventList(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	if events == nil {
		return nil, status.Errorf(http.StatusNotFound, "Events is empty")
	}
	eventstobesubscribed := new(importer.EventList)
	eventstobesubscribed.Events = events
	return eventstobesubscribed, nil
}

func (s *Server) SetFrequency(c context.Context, freqInfo *importer.FreqInfo) (*empty.Empty, error) {
	logrus.Info("Received SetFrequency")
	var ipAddress, token string
	var frequency uint32
	if freqInfo == nil || len(freqInfo.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input frequency info error")
	}
	ipAddress = freqInfo.IpAddress
	token = freqInfo.UserToken
	frequency = freqInfo.Frequency
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.setFrequency(ipAddress, token, frequency)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Frequency":       frequency,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) SubscribeGivenEvents(c context.Context, subeventlist *importer.GivenEventList) (*empty.Empty, error) {
	logrus.Info("Received SubsrcribeEvents")
	var token, ipAddress, eventServerAddr, eventServerPort string
	if subeventlist == nil || len(subeventlist.EventIpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input event data error")
	}
	ipAddress = subeventlist.EventIpAddress
	token = subeventlist.UserToken
	eventServerAddr = subeventlist.EventServerAddr
	eventServerPort = subeventlist.EventServerPort
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	if len(subeventlist.Events) <= 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Event is invalid")
	}
	statusCode, err := s.addSubscription(ipAddress, token, subeventlist.Events, eventServerAddr, eventServerPort)
	if err != nil && statusCode != http.StatusCreated {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) UnsubscribeGivenEvents(c context.Context, unsubeventlist *importer.GivenEventList) (*empty.Empty, error) {
	logrus.Info("Received UnSubsrcribeEvents")
	var token, ipAddress string
	if unsubeventlist == nil || len(unsubeventlist.EventIpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input event data error")
	}
	ipAddress = unsubeventlist.EventIpAddress
	token = unsubeventlist.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	if len(unsubeventlist.Events) <= 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Event is empty")
	}
	statusCode, err := s.removeSubscription(ipAddress, token, unsubeventlist.Events)
	if err != nil && statusCode != http.StatusCreated {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) DeleteDeviceList(c context.Context, device *importer.Device) (*empty.Empty, error) {
	var token, ipAddress string
	logrus.Info("DeleteDeviceList received")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = device.IpAddress
	token = device.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if _, ok := s.devicemap[ipAddress]; !ok {
		logrus.Infof("Device %s not found", ipAddress)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device "+ipAddress+" not found")
	}
	logrus.Infof("deleting device info file %s", ipAddress)
	err := s.removeDeviceFile(ipAddress, token)
	if err != nil {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(http.StatusNotFound), errStatus.Message())
	}
	logrus.Infof("deleting device data file %s", ipAddress)
	err = s.removeDeviceDataFile(ipAddress, token)
	if err != nil {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(http.StatusNotFound), errStatus.Message())
	}
	if s.devicemap[ipAddress].Model == RedfishPSMEModel {
		statusCode, err := s.setSessionService(ipAddress, token, false, uint64(RfSessionTimeOut))
		if err != nil && statusCode != http.StatusOK {
			errStatus, _ := status.FromError(err)
			logrus.WithFields(logrus.Fields{
				"IP address:port": ipAddress,
			}).Info(errStatus.Message())
			return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
		}
	}
	s.devicemap[ipAddress].Datacollector.quit <- true
	<-s.devicemap[ipAddress].Datacollector.getdataend
	delete(s.devicemap, ipAddress)
	return &empty.Empty{}, nil
}

func (s *Server) SendDeviceList(c context.Context, list *importer.DeviceList) (*empty.Empty, error) {
	for _, dev := range list.Device {
		var ipAddress string
		if dev == nil || len(dev.IpAddress) == 0 {
			return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "No Device found")
		} else {
			ipAddress = dev.IpAddress
		}
		if msg, ok := s.validateIPAddress(ipAddress); !ok {
			logrus.WithFields(logrus.Fields{
				"IP address:port": ipAddress}).Info(msg)
			return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
		}
		if s.vlidateDeviceRegistered(ipAddress) == true {
			logrus.WithFields(logrus.Fields{
				"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " already registered")
			return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" already registered")
		}
		if dev.Frequency > 0 && dev.Frequency < RfDataCollectThreshold {
			logrus.WithFields(logrus.Fields{
				"IP address:port": ipAddress}).Info("The frequency value is invalid")
			return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "The frequency is invalid")
		}
		d := device{
			Subscriptions: make(map[string]string),
			Freq:          dev.Frequency,
			Datacollector: scheduler{
				quit:       make(chan bool),
				getdataend: make(chan bool),
			},
			Freqchan:      make(chan uint32),
			UserLoginInfo: make(map[string]string),
		}
		s.devicemap[ipAddress] = &d
		logrus.Infof("Configuring  %s", ipAddress)
		/* if initial interval is 0, create a dummy ticker, which is stopped right away, so getdata is not nil */
		freq := dev.Frequency
		if freq == 0 {
			freq = RfDataCollectDummyInterval
		}
		s.devicemap[ipAddress].Datacollector.getdata = time.NewTicker(time.Duration(freq) * time.Second)
		if dev.Frequency == 0 {
			s.devicemap[ipAddress].Datacollector.getdata.Stop()
		}
		s.devicemap[ipAddress].DeviceDatafile = getDeviceDataFile(ipAddress)
		s.devicemap[ipAddress].QueryState = false
		go s.collectData(ipAddress)
		s.devicemap[ipAddress].Datafile = getDataFile(ipAddress)
		s.devicemap[ipAddress].RfAPIList = redfishResources
		s.updateDataFile(ipAddress)
	}
	return &empty.Empty{}, nil
}

func (s *Server) StartQueryDeviceData(c context.Context, account *importer.DeviceAccount) (*empty.Empty, error) {
	var userName, token, ipAddress string
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	ipAddress = account.IpAddress
	token = account.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName = s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.startQueryDeviceData(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) StopQueryDeviceData(c context.Context, account *importer.DeviceAccount) (*empty.Empty, error) {
	var userName, token, ipAddress string
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	ipAddress = account.IpAddress
	token = account.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName = s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.stopQueryDeviceData(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//GetCurrentDevices :
func (s *Server) GetCurrentDevices(c context.Context, e *importer.Empty) (*importer.DeviceListByIp, error) {
	logrus.Infof("In Received GetCurrentDevices")
	if len(s.devicemap) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "No Device found")
	}
	deviceList := new(importer.DeviceListByIp)
	for k, v := range s.devicemap {
		if v != nil {
			logrus.Infof("IpAdd[%s]", k)
			deviceList.IpAddress = append(deviceList.IpAddress, k)
		}
	}
	return deviceList, nil
}

//CreateDeviceUser :
func (s *Server) CreateDeviceAccount(c context.Context, account *importer.DeviceAccount) (*empty.Empty, error) {
	logrus.Infof("In Received CreateDeviceAccount")
	var token, newUsername, newPassword, ipAddress string
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	ipAddress = account.IpAddress
	newUsername = account.ActUsername
	newPassword = account.ActPassword
	token = account.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	if errRet := s.validateDeviceAccountData(ipAddress, newUsername, newPassword); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        newUsername,
			"Password":        newPassword,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.createDeviceAccount(ipAddress, token, newUsername, newPassword, account.Privilege)
	if err != nil && statusCode != http.StatusCreated {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"Username": newUsername,
			"Password": newPassword,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) RemoveDeviceAccount(c context.Context, account *importer.DeviceAccount) (*empty.Empty, error) {
	logrus.Infof("In Received RemoveDeviceAccount")
	var token, removeUser, ipAddress string
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	ipAddress = account.IpAddress
	token = account.UserToken
	removeUser = account.ActUsername
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	if errRet := s.validateDeviceAccountData(ipAddress, removeUser, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        removeUser,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.removeDeviceAccount(ipAddress, token, removeUser)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"Username": removeUser,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) LoginDevice(c context.Context, account *importer.DeviceAccount) (*importer.DeviceAccount, error) {
	logrus.Infof("In Received LoginDevice")
	deviceAccount := new(importer.DeviceAccount)
	var token, loginUserName, loginPassword, ipAddress string
	if account == nil || len(account.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	ipAddress = account.IpAddress
	loginUserName = account.ActUsername
	loginPassword = account.ActPassword
	//PSME supports to login user acount without HTTP token
	token = ""
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	if errRet := s.validateDeviceAccountData(ipAddress, loginUserName, loginPassword); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        loginUserName,
			"Password":        loginPassword,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	token, statusCode, err := s.loginDevice(ipAddress, token, loginUserName, loginPassword)
	if err != nil && statusCode != http.StatusCreated {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        loginUserName,
			"Password":        loginPassword,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceAccount.Httptoken = token
	return deviceAccount, nil
}

func (s *Server) LogoutDevice(c context.Context, account *importer.DeviceAccount) (*empty.Empty, error) {
	logrus.Infof("In Received LogoutDevice")
	var token, logoutUsername, ipAddress string
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	ipAddress = account.IpAddress
	token = account.UserToken
	logoutUsername = account.ActUsername
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	if errRet := s.validateDeviceAccountData(ipAddress, logoutUsername, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        logoutUsername,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.logoutDevice(ipAddress, token, logoutUsername)
	if err != nil && statusCode != http.StatusCreated {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
			"LogoutUsername":  logoutUsername,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) ChangeDeviceUserPassword(c context.Context, account *importer.DeviceAccount) (*empty.Empty, error) {
	logrus.Infof("In Received ChangeDeviceUserPassword")
	var token, password, userName, ipAddress string
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	ipAddress = account.IpAddress
	token = account.UserToken
	userName = account.ActUsername
	password = account.ActPassword
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	if errRet := s.validateDeviceAccountData(ipAddress, userName, password); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
			"Password":        password,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.changeDeviceUserPassword(ipAddress, token, userName, password)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"Username": userName,
			"Password": password,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) ListDeviceAccounts(c context.Context, account *importer.DeviceAccount) (*importer.DeviceAccountList, error) {
	var token, ipAddress string
	if account == nil || len(account.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	ipAddress = account.IpAddress
	token = account.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	deviceAccountLists := new(importer.DeviceAccountList)
	accountList, statusCode, err := s.listDeviceAccount(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": token,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	accounts := importer.DeviceAccountList{Account: accountList}
	deviceAccountLists.Account = accounts.Account
	return deviceAccountLists, nil
}

func (s *Server) SetSessionService(c context.Context, device *importer.DeviceAccount) (*empty.Empty, error) {
	var token, ipAddress string
	var sessionEnabled bool
	var sessionTimeout uint64
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = device.IpAddress
	token = device.UserToken
	sessionEnabled = device.SessionEnabled
	sessionTimeout = device.SessionTimeout
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.setSessionService(ipAddress, token, sessionEnabled, sessionTimeout)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"sessionEnabled":  sessionEnabled,
			"SessionTimeout":  sessionTimeout,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetDeviceData(c context.Context, device *importer.Device) (*importer.DeviceData, error) {
	var redfishAPI, token, ipAddress string
	var deviceData []string
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = device.IpAddress
	redfishAPI = device.RedfishAPI
	account := device.DeviceAccount
	if account == nil {
		return nil, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	token = account.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, deviceData, err := s.getDeviceDataByFileData(ipAddress, token, redfishAPI)
	if err != nil || statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Redfish API":     redfishAPI,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceRedfishData := new(importer.DeviceData)
	deviceRedfishData.DeviceData = deviceData
	return deviceRedfishData, nil
}

func (s *Server) GenericDeviceAccess(c context.Context, device *importer.Device) (*importer.HttpData, error) {
	logrus.Info("Received GenericDeviceAccess")
	var httpMethod, token, redfishAPI, ipAddress, httpDeleteData string
	deviceData := map[string]interface{}{}
	httpPostData := map[string]interface{}{}
	httpPatchData := map[string]interface{}{}
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = device.IpAddress
	redfishAPI = device.RedfishAPI
	account := device.DeviceAccount
	if account == nil {
		return nil, status.Errorf(http.StatusBadRequest, "input account data error")
	}
	token = account.UserToken
	httpInfo := device.HttpInfo
	if httpInfo != nil {
		httpMethod = httpInfo.HttpMethod
		if httpInfo.HttpPostData != nil {
			for k, v := range httpInfo.HttpPostData.PostData {
				httpPostData[k] = v
			}
		}
		if len(httpInfo.HttpDeleteData) != 0 {
			httpDeleteData = httpInfo.HttpDeleteData
		}
		if httpInfo.HttpPatchData != nil {
			for k, v := range httpInfo.HttpPatchData.PatchData {
				httpPatchData[k] = v
			}
		}
	}
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, deviceData, err := s.genericDeviceAccess(ipAddress, redfishAPI, token, httpMethod, httpPostData, httpDeleteData, httpPatchData)
	if err != nil {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port":  ipAddress,
			"Redfish API":      redfishAPI,
			"HTTP Method":      httpMethod,
			"HTTP POST Data":   httpPostData,
			"HTTP DELETE Data": httpDeleteData,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	if httpMethod == "DELETE" {
		return &importer.HttpData{
			ResultData: "",
		}, nil
	}
	if deviceData == nil {
		return nil, nil
	}
	var jsonData []byte
	jsonData, err = json.Marshal(deviceData)
	if err != nil {
		logrus.Errorf("Update data error %s", err)
		return nil, status.Errorf(codes.Code(http.StatusInternalServerError), "Update data error")
	}

	return &importer.HttpData{
		ResultData: string(jsonData),
	}, nil
}

func (s *Server) EnableLogServiceState(c context.Context, logDevice *importer.LogService) (*empty.Empty, error) {
	var token, ipAddress string
	var logServiceEnabled bool
	if logDevice == nil || len(logDevice.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = logDevice.IpAddress
	token = logDevice.UserToken
	logServiceEnabled = logDevice.LogServiceEnabled
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.changeDeviceLogService(ipAddress, token, logServiceEnabled)
	if err != nil && statusCode != http.StatusNoContent {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"ServiceEnabled":  logServiceEnabled,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) ResetDeviceLogData(c context.Context, logDevice *importer.LogService) (*empty.Empty, error) {
	var token, ipAddress string
	if logDevice == nil || len(logDevice.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = logDevice.IpAddress
	token = logDevice.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.resetDeviceLogData(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetDeviceLogData(c context.Context, logDevice *importer.LogService) (*importer.LogService, error) {
	var token, ipAddress string
	if logDevice == nil || len(logDevice.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = logDevice.IpAddress
	token = logDevice.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	logData, statusCode, err := s.getDeviceLogData(ipAddress, token)
	if err != nil && statusCode != http.StatusNoContent {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceLogData := new(importer.LogService)
	deviceLogData.LogData = logData
	return deviceLogData, nil
}

func (s *Server) SendDeviceSoftwareDownloadURI(c context.Context, softwareUpdate *importer.SoftwareUpdate) (*empty.Empty, error) {
	var token, ipAddress, softwareDownloadType, softwareDownloadURI string
	if softwareUpdate == nil || len(softwareUpdate.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input software update data error")
	}
	ipAddress = softwareUpdate.IpAddress
	token = softwareUpdate.UserToken
	softwareDownloadType = softwareUpdate.SoftwareDownloadType
	softwareDownloadURI = softwareUpdate.SoftwareDownloadURI
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.sendDeviceSoftwareDownloadURI(ipAddress, token, softwareDownloadType, softwareDownloadURI)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) AddPollingRfAPI(c context.Context, pollingRfAPI *importer.PollingRfAPI) (*empty.Empty, error) {
	var token, ipAddress, rfAPI string
	if pollingRfAPI == nil || len(pollingRfAPI.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input polling Redfish API data error")
	}
	ipAddress = pollingRfAPI.IpAddress
	token = pollingRfAPI.UserToken
	rfAPI = pollingRfAPI.RfAPI
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.addPollingRfAPI(ipAddress, token, rfAPI)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) RemovePollingRfAPI(c context.Context, pollingRfAPI *importer.PollingRfAPI) (*empty.Empty, error) {
	var token, ipAddress, rfAPI string
	if pollingRfAPI == nil || len(pollingRfAPI.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input polling Redfish API data error")
	}
	ipAddress = pollingRfAPI.IpAddress
	token = pollingRfAPI.UserToken
	rfAPI = pollingRfAPI.RfAPI
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.removePollingRfAPI(ipAddress, token, rfAPI)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetRfAPIList(c context.Context, pollingRfAPI *importer.PollingRfAPI) (*importer.RfAPIList, error) {
	var ipAddress, token string
	if pollingRfAPI == nil || len(pollingRfAPI.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input polling Redfish API data error")
	}
	ipAddress = pollingRfAPI.IpAddress
	token = pollingRfAPI.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(codes.Code(http.StatusBadRequest), msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	list, statusCode, err := s.getRfAPIList(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	if list == nil {
		return nil, status.Errorf(http.StatusNotFound, "The Redfish API list is empty")
	}
	rfAPIList := new(importer.RfAPIList)
	rfAPIList.RfAPIList = list
	return rfAPIList, nil
}

func (s *Server) GetDeviceBootData(c context.Context, systemBootData *importer.SystemBoot) (*importer.GrubBootData, error) {
	var token, ipAddress string
	if systemBootData == nil || len(systemBootData.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device boot data error")
	}
	ipAddress = systemBootData.IpAddress
	token = systemBootData.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	bootData, statusCode, err := s.getDeviceBootData(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	if bootData == nil {
		return nil, status.Errorf(http.StatusNotFound, "Failed to get the boot data")
	}
	grubBootData := new(importer.GrubBootData)
	grubBootData.BootData = bootData
	return grubBootData, nil
}

func (s *Server) GetDeviceDefaultBoot(c context.Context, systemBootData *importer.SystemBoot) (*importer.GrubBootData, error) {
	var token, ipAddress string
	if systemBootData == nil || len(systemBootData.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device boot data error")
	}
	ipAddress = systemBootData.IpAddress
	token = systemBootData.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	defaultBoot, statusCode, err := s.getDeviceDefaultBoot(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	if defaultBoot == nil {
		return nil, status.Errorf(http.StatusNotFound, "Failed to get the default boot")
	}
	grubBootData := new(importer.GrubBootData)
	grubBootData.DefaultBoot = strings.Join(defaultBoot, " ")
	return grubBootData, nil
}

func (s *Server) SetDeviceDefaultBoot(c context.Context, systemBootData *importer.SystemBoot) (*empty.Empty, error) {
	var token, ipAddress, defaultBoot string
	if systemBootData == nil || len(systemBootData.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input device default boot data error")
	}
	ipAddress = systemBootData.IpAddress
	token = systemBootData.UserToken
	defaultBoot = systemBootData.DefaultBoot
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.setDeviceDefaultBoot(ipAddress, token, defaultBoot)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Default Boot":    defaultBoot,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) ResetDeviceSystem(c context.Context, systemBootData *importer.SystemBoot) (*empty.Empty, error) {
	var token, ipAddress, resetType string
	if systemBootData == nil || len(systemBootData.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input device reset data error")
	}
	ipAddress = systemBootData.IpAddress
	token = systemBootData.UserToken
	resetType = systemBootData.ResetType
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.resetDeviceSystem(ipAddress, token, resetType)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Reset type":      resetType,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) ConfigureBootSource(c context.Context, systemBootData *importer.SystemBoot) (*empty.Empty, error) {
	var token, ipAddress string
	if systemBootData == nil || len(systemBootData.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input device reset data error")
	}
	ipAddress = systemBootData.IpAddress
	token = systemBootData.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "This function does not support now")
}

func (s *Server) GetDeviceTemperatures(c context.Context, deviceTemperature *importer.DeviceTemperature) (*importer.DeviceTemperature, error) {
	var token, ipAddress string
	if deviceTemperature == nil || len(deviceTemperature.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = deviceTemperature.IpAddress
	token = deviceTemperature.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	deviceTemp, statusCode, err := s.getDeviceTemperature(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceTempData := new(importer.DeviceTemperature)
	deviceTempData.TempData = deviceTemp
	return deviceTempData, nil
}

func (s *Server) SetDeviceTemperatureForEvent(c context.Context, deviceTemperature *importer.DeviceTemperature) (*empty.Empty, error) {
	var ipAddress, token, memberId string
	var upperThresholdNonCritical, lowerThresholdNonCritical uint32
	if deviceTemperature == nil || len(deviceTemperature.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input info error")
	}
	ipAddress = deviceTemperature.IpAddress
	token = deviceTemperature.UserToken
	memberId = deviceTemperature.MemberId
	upperThresholdNonCritical = deviceTemperature.UpperThresholdNonCritical
	lowerThresholdNonCritical = deviceTemperature.LowerThresholdNonCritical
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.setDeviceTemperatureForEvent(ipAddress, token, memberId, upperThresholdNonCritical, lowerThresholdNonCritical)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port":           ipAddress,
			"MemberId":                  memberId,
			"UpperThresholdNonCritical": upperThresholdNonCritical,
			"LowerThresholdNonCritical": lowerThresholdNonCritical,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

func (s *Server) GetRedfishModel(c context.Context, redfishInfo *importer.RedfishInfo) (*importer.RedfishInfo, error) {
	var token, ipAddress string
	if redfishInfo == nil || len(redfishInfo.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = redfishInfo.IpAddress
	token = redfishInfo.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	model, statusCode, err := s.getRedfishModel(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Model":           model,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	redfishInfoData := new(importer.RedfishInfo)
	redfishInfoData.RedfishModel = model
	return redfishInfoData, nil
}

func (s *Server) GetCpuUsage(c context.Context, redfishInfo *importer.RedfishInfo) (*importer.RedfishInfo, error) {
	var token, ipAddress string
	if redfishInfo == nil || len(redfishInfo.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "input device data error")
	}
	ipAddress = redfishInfo.IpAddress
	token = redfishInfo.UserToken
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return nil, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return nil, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return nil, status.Errorf(http.StatusBadRequest, errRet)
	}
	usage, statusCode, err := s.getCpuUsage(ipAddress, token)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"CPU Usage":       usage,
		}).Info(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	redfishInfoData := new(importer.RedfishInfo)
	redfishInfoData.CpuUsage = usage
	return redfishInfoData, nil

}

func (s *Server) SetCpuUsageForEvent(c context.Context, deviceCpuUsage *importer.DeviceCpuUsage) (*empty.Empty, error) {
	var ipAddress, token string
	var upperThresholdNonCritical uint32
	if deviceCpuUsage == nil || len(deviceCpuUsage.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "input info error")
	}
	ipAddress = deviceCpuUsage.IpAddress
	token = deviceCpuUsage.UserToken
	upperThresholdNonCritical = deviceCpuUsage.UpperThresholdNonCritical
	if msg, ok := s.validateIPAddress(ipAddress); !ok {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info(msg)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
	}
	if s.vlidateDeviceRegistered(ipAddress) == false {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress}).Info("Device ip " + ipAddress + " is not registered")
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, "Device ip "+ipAddress+" is not registered")
	}
	userName := s.getUserByToken(ipAddress, token)
	if errRet := s.validateDeviceAccountData(ipAddress, userName, ""); errRet != "" {
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
		}).Info(errRet)
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, errRet)
	}
	statusCode, err := s.setCpuUsageForEvent(ipAddress, token, upperThresholdNonCritical)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port":           ipAddress,
			"UpperThresholdNonCritical": upperThresholdNonCritical,
		}).Info(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}
