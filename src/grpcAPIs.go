/*Edgecore DeviceManager
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
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	manager "devicemanager/proto"

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

type AuthType struct {
	TOKEN int
	BASIC int
	NONE  int
}

var authTypeEnum = &AuthType{TOKEN: 0, BASIC: 1, NONE: 2}

type userAuth struct {
	AuthType int    `json:"authType"`
	Token    string `json:"token"`
	UserName string `json:"userName"`
	Password string `json:"password"`
	PassAuth bool   `json:"passAuth"`
}

type device struct {
	Freq               uint32              `json:"frequency"`
	Datacollector      scheduler           `json:"-"`
	Freqchan           chan uint32         `json:"-"`
	Datafile           *os.File            `json:"-"`
	DeviceDatafile     *os.File            `json:"-"`
	UserLoginInfo      map[string]userAuth `json:"userlogin"`
	QueryState         bool                `json:"-"`
	QueryUser          userAuth            `json:"-"`
	DeviceLockFile     sync.Mutex          `json:"-"`
	DeviceDataLockFile sync.Mutex          `json:"-"`
	RfAPIList          []string            `json:"redfishAPIList"`
	ContentType        string              `json:"ContentType"`
	HTTPType           string              `json:"HTTPType"`
	UserAuthLock       sync.Mutex          `json:"-"`
	PassAuth           bool                `json:"passAuth"`
}

//Server ...
type Server struct {
	devicemap    map[string]*device
	gRPCserver   *grpc.Server
	dataproducer sarama.AsyncProducer
}

//DefaultDetectDevice ...
const DefaultDetectDevice = true

//SetHTTPType ...
func (s *Server) SetHTTPType(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received SetHTTPType")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := device.IpAddress
	httpType := device.HTTPType
	funcs := []string{"checkIPAddress", "checkRegistered"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, "", ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	if len(httpType) == 0 {
		return &empty.Empty{}, errors.New(ErrHTTPTypeEmpty.String())
	}
	if httpType != "http" && httpType != "https" {
		return &empty.Empty{}, errors.New(ErrHTTPType.String())
	}
	httpType = httpType + "://"
	s.devicemap[ipAddress].HTTPType = httpType
	RfProtocol[ipAddress] = s.devicemap[ipAddress].HTTPType
	s.updateDataFile(ipAddress)
	return &empty.Empty{}, nil
}

//GetHTTPType ...
func (s *Server) GetHTTPType(c context.Context, device *manager.Device) (*manager.Device, error) {
	logrus.Info("Received GetHTTPType")
	var ipAddress string
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress = device.IpAddress
	funcs := []string{"checkIPAddress", "checkRegistered"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, "", ""); err != nil {
			return nil, err
		}
	}
	deviceData := new(manager.Device)
	if deviceData != nil {
		deviceData.HTTPType = s.devicemap[ipAddress].HTTPType
	}
	return deviceData, nil
}

//SetHTTPApplication...
func (s *Server) SetHTTPApplication(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received SetHTTPApplication")
	var ipAddress, contentType string
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress = device.IpAddress
	contentType = device.ContentType
	funcs := []string{"checkIPAddress", "checkRegistered"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, "", ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	if len(contentType) == 0 {
		return &empty.Empty{}, errors.New(ErrHTTPApplicationEmpty.String())
	}
	s.devicemap[ipAddress].ContentType = contentType
	ContentType[ipAddress] = s.devicemap[ipAddress].ContentType
	s.updateDataFile(ipAddress)
	return &empty.Empty{}, nil
}

//GetHTTPApplication...
func (s *Server) GetHTTPApplication(c context.Context, device *manager.Device) (*manager.Device, error) {
	logrus.Info("Received GetHTTPApplication")
	var ipAddress string
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress = device.IpAddress
	funcs := []string{"checkIPAddress", "checkRegistered"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, "", ""); err != nil {
			return nil, err
		}
	}
	deviceData := new(manager.Device)
	if deviceData != nil {
		deviceData.ContentType = s.devicemap[ipAddress].ContentType
	}
	return deviceData, nil
}

//SetFrequency ...
func (s *Server) SetFrequency(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received SetFrequency")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrFreqValueInvalid.String())
	}
	ipAddress := device.IpAddress
	frequency := device.Frequency
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	if _, err := s.getFunctionsResult("userPrivilegeOnlyUsers", ipAddress, authStr, ErrUserPrivilege.String()); err != nil {
		return &empty.Empty{}, err
	}
	statusCode, err := s.setFrequency(ipAddress, frequency)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Frequency":       frequency,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//SimpleUpdate ...
func (s *Server) SimpleUpdate(c context.Context, request *manager.SimpleUpdateRequest) (*manager.Task, error) {
	logrus.Info("Received RPC call for SimpleUpdate")
	ipAddress := request.IpAddress
	if request == nil || len(ipAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, "Device ip address is missing")
	}
	authToken := request.UserOrToken

	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus", "userPrivilegeOnlyUsers"}
	functionArgs := [][]string{{""}, {""}, {""}, {""}, {"", ErrUserPrivilege.String()}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authToken, functionArgs[id]...); err != nil {
			return nil, err
		}
	}

	updateService := &UpdateService{
		Server: s,
	}
	simpleUpdateRequest := SimpleUpdateRequest{
		ImageURI:         request.ImageURI,
		TransferProtocol: request.TransferProtocol,
		Targets:          request.Targets,
		Username:         request.Username,
		Password:         request.Password,
	}
	taskURI, err := updateService.SimpleUpdate(ipAddress, authToken, simpleUpdateRequest)

	if err != nil {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return nil, status.Error(codes.Code(http.StatusInternalServerError), errStatus.Message())
	}
	return &manager.Task{TaskURI: taskURI}, nil
}

//DeleteDeviceList ...
func (s *Server) DeleteDeviceList(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received DeleteDeviceList")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := device.IpAddress
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus", "userPrivilegeAdmin"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	logrus.Infof("deleting device info file %s", ipAddress)
	err := s.removeDeviceFile(ipAddress)
	if err != nil {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(http.StatusNotFound), errStatus.Message())
	}
	logrus.Infof("deleting device data file %s", ipAddress)
	err = s.removeDeviceDataFile(ipAddress)
	if err != nil {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(http.StatusNotFound), errStatus.Message())
	}
	statusCode, err := s.setSessionService(ipAddress, authStr, false, uint64(RfSessionTimeOut))
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	s.devicemap[ipAddress].Datacollector.quit <- true
	<-s.devicemap[ipAddress].Datacollector.getdataend
	delete(s.devicemap, ipAddress)
	return &empty.Empty{}, nil
}

//SendDeviceList ...
func (s *Server) SendDeviceList(c context.Context, list *manager.DeviceList) (*empty.Empty, error) {
	logrus.Info("Received SendDeviceList")
	for _, dev := range list.Device {
		var ipAddress string
		if dev == nil || len(dev.IpAddress) == 0 {
			return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrNoDevice.String())
		}
		ipAddress = dev.IpAddress
		detectDevice := dev.DetectDevice
		if msg, ok := s.validateIPAddress(ipAddress, detectDevice); !ok {
			logrus.WithFields(logrus.Fields{
				"IP address:port": ipAddress}).Error(msg)
			return &empty.Empty{}, status.Errorf(http.StatusBadRequest, msg)
		}
		if s.vlidateDeviceRegistered(ipAddress) == true {
			logrus.WithFields(logrus.Fields{
				"IP address:port": ipAddress}).Error(ErrHasRegistered.String(ipAddress))
			return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrHasRegistered.String(ipAddress))
		}
		if dev.Frequency > 0 && dev.Frequency < RfDataCollectThreshold {
			logrus.WithFields(logrus.Fields{
				"IP address:port": ipAddress}).Error(ErrFreqValueInvalid.String())
			return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrFreqValueInvalid.String())
		}
		d := device{
			Freq: dev.Frequency,
			Datacollector: scheduler{
				quit:       make(chan bool),
				getdataend: make(chan bool),
			},
			Freqchan:      make(chan uint32),
			UserLoginInfo: make(map[string]userAuth),
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
		s.devicemap[ipAddress].PassAuth = dev.PassAuth
		s.devicemap[ipAddress].DeviceDatafile = getDeviceDataFile(ipAddress)
		s.devicemap[ipAddress].QueryState = false
		go s.collectData(ipAddress)
		s.devicemap[ipAddress].Datafile = getDataFile(ipAddress)
		s.devicemap[ipAddress].RfAPIList = redfishResources
		RfProtocol[ipAddress] = RfDefaultHttpsProtocol
		s.devicemap[ipAddress].HTTPType = RfDefaultHttpsProtocol
		ContentType[ipAddress] = DefaultContentType
		s.devicemap[ipAddress].ContentType = DefaultContentType
		s.updateDataFile(ipAddress)
	}
	return &empty.Empty{}, nil
}

//StartQueryDeviceData ...
func (s *Server) StartQueryDeviceData(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received StartQueryDeviceData")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrAccountData.String())
	}
	ipAddress := device.IpAddress
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.startQueryDeviceData(ipAddress, authStr)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//StopQueryDeviceData ...
func (s *Server) StopQueryDeviceData(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received StopQueryDeviceData")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrAccountData.String())
	}
	ipAddress := device.IpAddress
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.stopQueryDeviceData(ipAddress)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//GetCurrentDevices :
func (s *Server) GetCurrentDevices(c context.Context, e *manager.Empty) (*manager.DeviceListByIp, error) {
	logrus.Infof("In Received GetCurrentDevices")
	if len(s.devicemap) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrNoDevice.String())
	}
	deviceList := new(manager.DeviceListByIp)
	for k, v := range s.devicemap {
		if v != nil {
			logrus.Infof("IpAdd[%s]", k)
			deviceList.IpAddress = append(deviceList.IpAddress, k)
		}
	}
	return deviceList, nil
}

//CreateDeviceAccount ...
func (s *Server) CreateDeviceAccount(c context.Context, account *manager.DeviceAccount) (*empty.Empty, error) {
	logrus.Info("Received CreateDeviceAccount")
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrAccountData.String())
	}
	ipAddress := account.IpAddress
	newUsername := account.ActUsername
	newPassword := account.ActPassword
	var authStr string
	authStr = account.UserOrToken
	var userName string
	funcs := []string{"checkIPAddress", "checkRegistered"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	if authData := s.getUserAuthData(ipAddress, authStr); (authData != userAuth{}) {
		userName = authData.UserName
	} else {
		userName = s.getUserByToken(ipAddress, authStr)
	}
	funcs = []string{"checkAccount", "checkAccount", "userStatus", "loginStatus", "userPrivilegeAdmin"}
	functionArgs := [][]string{{userName, ""}, {newUsername, newPassword}, {""}, {""}, {""}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.createDeviceAccount(ipAddress, authStr, newUsername, newPassword, account.Privilege)
	if err != nil && statusCode != http.StatusCreated {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"Username": newUsername,
			"Password": newPassword,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//RemoveDeviceAccount ...
func (s *Server) RemoveDeviceAccount(c context.Context, account *manager.DeviceAccount) (*empty.Empty, error) {
	logrus.Info("Received RemoveDeviceAccount")
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrAccountData.String())
	}
	ipAddress := account.IpAddress
	removeUser := account.ActUsername
	var authStr string
	authStr = account.UserOrToken
	var userName string
	funcs := []string{"checkIPAddress", "checkRegistered"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	if authData := s.getUserAuthData(ipAddress, authStr); (authData != userAuth{}) {
		userName = authData.UserName
	} else {
		userName = s.getUserByToken(ipAddress, authStr)
	}
	if userName == removeUser {
		logrus.Errorf(ErrDeleteUserSelf.String(userName))
		return &empty.Empty{}, errors.New(ErrDeleteUserSelf.String(userName))
	}
	funcs = []string{"checkAccount", "checkAccount", "userStatus", "loginStatus", "userPrivilegeAdmin"}
	functionArgs := [][]string{{userName, ""}, {removeUser, ""}, {removeUser}, {userName}, {""}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.removeDeviceAccount(ipAddress, authStr, removeUser)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"Username": removeUser,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//LoginDevice ...
func (s *Server) LoginDevice(c context.Context, account *manager.DeviceAccount) (*manager.DeviceAccount, error) {
	logrus.Info("Received LoginDevice")
	if account == nil || len(account.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrAccountData.String())
	}
	ipAddress := account.IpAddress
	loginUserName := account.ActUsername
	loginPassword := account.ActPassword
	funcs := []string{"checkIPAddress", "checkRegistered"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, "", ""); err != nil {
			return nil, err
		}
	}
	var basicAuthEnabled bool = false
	if account.BasicAuth != nil && account.BasicAuth.Enabled {
		basicAuthEnabled = account.BasicAuth.Enabled
	}
	token, statusCode, err := s.loginDevice(ipAddress, loginUserName, loginPassword, basicAuthEnabled)
	if err != nil && statusCode != http.StatusCreated {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        loginUserName,
			"Password":        loginPassword,
		}).Error(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceAccount := new(manager.DeviceAccount)
	deviceAccount.Httptoken = token
	return deviceAccount, nil
}

//LogoutDevice ...
func (s *Server) LogoutDevice(c context.Context, account *manager.DeviceAccount) (*empty.Empty, error) {
	logrus.Info("Received LogoutDevice")
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrAccountData.String())
	}
	ipAddress := account.IpAddress
	var authStr string
	authStr = account.UserOrToken
	logoutUsername := account.ActUsername
	funcs := []string{"checkIPAddress", "checkRegistered"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	userName := s.getUserByToken(ipAddress, authStr)
	funcs = []string{"loginStatus", "loginStatus", "userStatus", "userStatus"}
	functionArgs := []string{userName, logoutUsername, userName, logoutUsername}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]); err != nil {
			return &empty.Empty{}, err
		}
	}
	if _, err := s.getFunctionsResult("userPrivilegeByUser", ipAddress, authStr, userName, logoutUsername,
		ErrUserHigherPrivilege.String()); err != nil {
		return &empty.Empty{}, err
	}
	statusCode, err := s.logoutDevice(ipAddress, authStr, logoutUsername)
	if err != nil && statusCode != http.StatusCreated {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Username":        userName,
			"LogoutUsername":  logoutUsername,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//ChangeDeviceUserPassword ...
func (s *Server) ChangeDeviceUserPassword(c context.Context, account *manager.DeviceAccount) (*empty.Empty, error) {
	logrus.Info("Received ChangeDeviceUserPassword")
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrAccountData.String())
	}
	ipAddress := account.IpAddress
	userName := account.ActUsername
	password := account.ActPassword
	var authStr string
	authStr = account.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus", "checkAccount"}
	functionArgs := [][]string{{""}, {""}, {userName}, {""}, {userName, password}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	if _, err := s.getFunctionsResult("userPrivilegeAdmin", ipAddress, authStr, ""); err != nil {
		return &empty.Empty{}, err
	}
	statusCode, err := s.changeDeviceUserPassword(ipAddress, authStr, userName, password)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"Username": userName,
			"Password": password,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//ListDeviceAccounts ...
func (s *Server) ListDeviceAccounts(c context.Context, account *manager.DeviceAccount) (*manager.DeviceAccountList, error) {
	logrus.Info("Received ListDeviceAccounts")
	if account == nil || len(account.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrAccountData.String())
	}
	ipAddress := account.IpAddress
	var authStr string
	authStr = account.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus", "userPrivilegeAdmin"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return nil, err
		}
	}
	deviceAccountLists := new(manager.DeviceAccountList)
	accountList, statusCode, err := s.listDeviceAccount(ipAddress, authStr)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	accounts := manager.DeviceAccountList{Account: accountList}
	deviceAccountLists.Account = accounts.Account
	return deviceAccountLists, nil
}

//SetSessionService ...
func (s *Server) SetSessionService(c context.Context, account *manager.DeviceAccount) (*empty.Empty, error) {
	logrus.Info("Received SetSessionService")
	if account == nil || len(account.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := account.IpAddress
	sessionEnabled := account.SessionEnabled
	sessionTimeout := account.SessionTimeout
	var authStr string
	authStr = account.UserOrToken
	if len(authStr) != 0 {
		funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus", "userPrivilegeAdmin"}
		for _, f := range funcs {
			if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
				return &empty.Empty{}, err
			}
		}
	}
	statusCode, err := s.setSessionService(ipAddress, authStr, sessionEnabled, sessionTimeout)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"sessionEnabled":  sessionEnabled,
			"SessionTimeout":  sessionTimeout,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//GetDeviceData ...
func (s *Server) GetDeviceData(c context.Context, device *manager.Device) (*manager.DeviceData, error) {
	logrus.Info("Received GetDeviceData")
	var deviceData []string
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := device.IpAddress
	redfishAPI := device.RedfishAPI
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return nil, err
		}
	}
	statusCode, deviceData, err := s.getDeviceDataByFileData(ipAddress, redfishAPI)
	if err != nil || statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Redfish API":     redfishAPI,
		}).Error(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceRedfishData := new(manager.DeviceData)
	deviceRedfishData.DeviceData = deviceData
	return deviceRedfishData, nil
}

//GenericDeviceAccess ...
func (s *Server) GenericDeviceAccess(c context.Context, device *manager.Device) (*manager.HttpData, error) {
	logrus.Info("Received GenericDeviceAccess")
	var httpMethod, httpDeleteData string
	deviceData := map[string]interface{}{}
	httpPostData := map[string]interface{}{}
	httpPatchData := map[string]interface{}{}
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := device.IpAddress
	redfishAPI := device.RedfishAPI
	var authStr string
	authStr = device.UserOrToken
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
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return nil, err
		}
	}
	statusCode, deviceData, err := s.genericDeviceAccess(ipAddress, redfishAPI, authStr, httpMethod, httpPostData, httpDeleteData, httpPatchData)
	if err != nil {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port":  ipAddress,
			"Redfish API":      redfishAPI,
			"HTTP Method":      httpMethod,
			"HTTP POST Data":   httpPostData,
			"HTTP DELETE Data": httpDeleteData,
		}).Error(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	if httpMethod == "DELETE" {
		return &manager.HttpData{
			ResultData: "",
		}, nil
	}
	if deviceData == nil {
		return nil, nil
	}
	var jsonData []byte
	jsonData, err = json.Marshal(deviceData)
	if err != nil {
		logrus.Errorf(ErrConvertData.String(err.Error()))
		return nil, status.Errorf(codes.Code(http.StatusInternalServerError), ErrConvertData.String(err.Error()))
	}
	return &manager.HttpData{
		ResultData: string(jsonData),
	}, nil
}

//EnableLogServiceState ...
func (s *Server) EnableLogServiceState(c context.Context, logDevice *manager.LogService) (*empty.Empty, error) {
	logrus.Info("Received EnableLogServiceState")
	if logDevice == nil || len(logDevice.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := logDevice.IpAddress
	id := logDevice.Id
	logServiceEnabled := logDevice.LogServiceEnabled
	var authStr string
	authStr = logDevice.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus", "userPrivilegeOnlyUsers"}
	functionArgs := [][]string{{""}, {""}, {""}, {""}, {"", ErrUserPrivilege.String()}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.changeDeviceLogService(ipAddress, authStr, id, logServiceEnabled)
	if err != nil && statusCode != http.StatusNoContent {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Log Member Id":   id,
			"ServiceEnabled":  logServiceEnabled,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//ResetDeviceLogData ...
func (s *Server) ResetDeviceLogData(c context.Context, logDevice *manager.LogService) (*empty.Empty, error) {
	logrus.Info("Received ResetDeviceLogData")
	if logDevice == nil || len(logDevice.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := logDevice.IpAddress
	id := logDevice.Id
	var authStr string
	authStr = logDevice.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus", "userPrivilegeOnlyUsers"}
	functionArgs := [][]string{{""}, {""}, {""}, {""}, {"", ErrUserPrivilege.String()}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.resetDeviceLogData(ipAddress, authStr, id)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Log Member Id":   id,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//GetDeviceLogData ...
func (s *Server) GetDeviceLogData(c context.Context, logDevice *manager.LogService) (*manager.LogService, error) {
	logrus.Info("Received GetDeviceLogData")
	if logDevice == nil || len(logDevice.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := logDevice.IpAddress
	id := logDevice.Id
	var authStr string
	authStr = logDevice.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return nil, err
		}
	}
	logData, statusCode, err := s.getDeviceLogData(ipAddress, authStr, id)
	if err != nil && statusCode != http.StatusNoContent {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Log Member Id":   id,
		}).Error(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceLogData := new(manager.LogService)
	deviceLogData.LogData = logData
	return deviceLogData, nil
}

//SendDeviceSoftwareDownloadURI ...
func (s *Server) SendDeviceSoftwareDownloadURI(c context.Context, softwareUpdate *manager.SoftwareUpdate) (*empty.Empty, error) {
	logrus.Info("Received SendDeviceSoftwareDownloadURI")
	if softwareUpdate == nil || len(softwareUpdate.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrSWDataEmpty.String())
	}
	ipAddress := softwareUpdate.IpAddress
	softwareDownloadType := softwareUpdate.SoftwareDownloadType
	softwareDownloadURI := softwareUpdate.SoftwareDownloadURI
	var authStr string
	authStr = softwareUpdate.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "userStatus", "loginStatus", "userPrivilegeOnlyUsers"}
	functionArgs := [][]string{{""}, {""}, {""}, {""}, {"", ErrUserPrivilege.String()}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.sendDeviceSoftwareDownloadURI(ipAddress, authStr, softwareDownloadType, softwareDownloadURI)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//AddPollingRfAPI ...
func (s *Server) AddPollingRfAPI(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received AddPollingRfAPI")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrRfAPIEmpty.String())
	}
	ipAddress := device.IpAddress
	rfAPI := device.PollingDataRfAPI
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus", "userPrivilegeOnlyUsers"}
	functionArgs := [][]string{{""}, {""}, {""}, {""}, {"", ErrUserPrivilege.String()}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.addPollingRfAPI(ipAddress, authStr, rfAPI)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//RemovePollingRfAPI ...
func (s *Server) RemovePollingRfAPI(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received RemovePollingRfAPI")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrRfAPIEmpty.String())
	}
	ipAddress := device.IpAddress
	rfAPI := device.PollingDataRfAPI
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus", "userPrivilegeOnlyUsers"}
	functionArgs := [][]string{{""}, {""}, {""}, {""}, {"", ErrUserPrivilege.String()}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.removePollingRfAPI(ipAddress, rfAPI)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Redfish API":     rfAPI,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//ClearPollingRfAPI ...
func (s *Server) ClearPollingRfAPI(c context.Context, device *manager.Device) (*empty.Empty, error) {
	logrus.Info("Received ClearPollingRfAPI")
	if device == nil || len(device.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrRfAPIEmpty.String())
	}
	ipAddress := device.IpAddress
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus", "userPrivilegeOnlyUsers"}
	functionArgs := [][]string{{""}, {""}, {""}, {""}, {"", ErrUserPrivilege.String()}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.clearPollingRfAPI(ipAddress)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//GetRfAPIList ...
func (s *Server) GetRfAPIList(c context.Context, device *manager.Device) (*manager.RfAPIList, error) {
	logrus.Info("Received GetRfAPIList")
	if device == nil || len(device.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrRfAPIEmpty.String())
	}
	ipAddress := device.IpAddress
	var authStr string
	authStr = device.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return nil, err
		}
	}
	list, statusCode, err := s.getRfAPIList(ipAddress)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	if list == nil {
		return nil, status.Errorf(http.StatusNotFound, ErrRfAPIEmpty.String())
	}
	rfAPIList := new(manager.RfAPIList)
	rfAPIList.RfAPIList = list
	return rfAPIList, nil
}

//GetDeviceSupportedResetType ...
func (s *Server) GetDeviceSupportedResetType(c context.Context, systemBootData *manager.SystemBoot) (*manager.SystemBoot, error) {
	logrus.Info("Received GetDeviceSupportedResetType")
	if systemBootData == nil || len(systemBootData.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := systemBootData.IpAddress
	var authStr string
	authStr = systemBootData.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return nil, err
		}
	}
	deviceResetType, statusCode, err := s.getDeviceSupportedResetType(ipAddress, authStr)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceResetTypeData := new(manager.SystemBoot)
	deviceResetTypeData.SupportedResetType = deviceResetType
	return deviceResetTypeData, nil
}

//ResetDeviceSystem ...
func (s *Server) ResetDeviceSystem(c context.Context, systemBootData *manager.SystemBoot) (*empty.Empty, error) {
	logrus.Info("Received ResetDeviceSystem")
	if systemBootData == nil || len(systemBootData.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrResetTypeEmpty.String())
	}
	ipAddress := systemBootData.IpAddress
	resetType := systemBootData.ResetType
	var authStr string
	authStr = systemBootData.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus", "userPrivilegeAdmin"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.resetDeviceSystem(ipAddress, authStr, resetType)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
			"Reset type":      resetType,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}

//GetDeviceTemperatures ...
func (s *Server) GetDeviceTemperatures(c context.Context, deviceTemperature *manager.DeviceTemperature) (*manager.DeviceTemperature, error) {
	logrus.Info("Received GetDeviceTemperatures")
	if deviceTemperature == nil || len(deviceTemperature.IpAddress) == 0 {
		return nil, status.Errorf(http.StatusBadRequest, ErrDeviceData.String())
	}
	ipAddress := deviceTemperature.IpAddress
	var authStr string
	authStr = deviceTemperature.UserOrToken
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus"}
	for _, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, ""); err != nil {
			return nil, err
		}
	}
	deviceTemp, statusCode, err := s.getDeviceTemperature(ipAddress, authStr)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port": ipAddress,
		}).Error(errStatus.Message())
		return nil, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	deviceTempData := new(manager.DeviceTemperature)
	deviceTempData.TempData = deviceTemp
	return deviceTempData, nil
}

//SetDeviceTemperatureForEvent ...
func (s *Server) SetDeviceTemperatureForEvent(c context.Context, deviceTemperature *manager.DeviceTemperature) (*empty.Empty, error) {
	logrus.Info("Received SetDeviceTemperatureForEvent")
	if deviceTemperature == nil || len(deviceTemperature.IpAddress) == 0 {
		return &empty.Empty{}, status.Errorf(http.StatusBadRequest, ErrEventTemperInvalid.String())
	}
	ipAddress := deviceTemperature.IpAddress
	memberID := deviceTemperature.MemberID
	authStr := deviceTemperature.UserOrToken
	upperThresholdNonCritical := deviceTemperature.UpperThresholdNonCritical
	lowerThresholdNonCritical := deviceTemperature.LowerThresholdNonCritical
	funcs := []string{"checkIPAddress", "checkRegistered", "loginStatus", "userStatus", "userPrivilegeOnlyUsers"}
	functionArgs := [][]string{{""}, {""}, {""}, {""}, {"", ErrUserPrivilege.String()}}
	for id, f := range funcs {
		if _, err := s.getFunctionsResult(f, ipAddress, authStr, functionArgs[id]...); err != nil {
			return &empty.Empty{}, err
		}
	}
	statusCode, err := s.setDeviceTemperatureForEvent(ipAddress, authStr, memberID, upperThresholdNonCritical, lowerThresholdNonCritical)
	if err != nil && statusCode != http.StatusOK {
		errStatus, _ := status.FromError(err)
		logrus.WithFields(logrus.Fields{
			"IP address:port":           ipAddress,
			"MemberID":                  memberID,
			"UpperThresholdNonCritical": upperThresholdNonCritical,
			"LowerThresholdNonCritical": lowerThresholdNonCritical,
		}).Error(errStatus.Message())
		return &empty.Empty{}, status.Errorf(codes.Code(statusCode), errStatus.Message())
	}
	return &empty.Empty{}, nil
}
