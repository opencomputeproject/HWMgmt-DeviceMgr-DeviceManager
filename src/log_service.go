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
	"errors"
	"net/http"
	"strconv"

	logrus "github.com/sirupsen/logrus"
)

//RfManager
const RfManager = "/redfish/v1/Managers/"

//RfLogService
const RfLogService = RfManager + "1/LogServices/1/"

func (s *Server) checkLogServiceState(deviceIPAddress string, token string) (state bool) {
	logState := s.getDeviceData(deviceIPAddress, RfLogService, token, 1, "ServiceEnabled")
	if logState == nil {
		logrus.Errorf("Failed to get device log service state from this device %s", deviceIPAddress)
		return false
	}
	state, _ = strconv.ParseBool(logState[0])
	return state
}

func (s *Server) changeDeviceLogService(deviceIPAddress string, token string, state bool) (statusCode int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " is not available in deivce")
	}
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] && userPrivilege != UserPrivileges[1] {
		logrus.Errorf("The user %s privilege could not change Log sevice state from this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user privilege could not change state from  this device")
	}
	if s.checkLogServiceState(deviceIPAddress, token) == state {
		logrus.Errorf("The log service state has in the " + strconv.FormatBool(state) + " from device " + deviceIPAddress)
		return http.StatusBadRequest, errors.New("The log service state has in the " + strconv.FormatBool(state) + " from device " + deviceIPAddress)
	}
	ServiceInfo := map[string]interface{}{}
	ServiceInfo["ServiceEnabled"] = state
	_, _, _, statusCode = patchHTTPDataByRfAPI(deviceIPAddress, RfLogService, token, ServiceInfo)
	if statusCode != http.StatusNoContent {
		logrus.Errorf("Failed to set log service state to device %s, status code %d", deviceIPAddress, statusCode)
		return statusCode, errors.New("Failed to set log service state to device " + deviceIPAddress)
	}
	return statusCode, nil
}

func (s *Server) resetDeviceLogData(deviceIPAddress string, token string) (statusCode int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " is not available in deivce")
	}
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] && userPrivilege != UserPrivileges[1] {
		logrus.Errorf("The user %s privilege could not change Log sevice state from this device %s", deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user privilege could not change state from  this device")
	}
	ServiceInfo := map[string]interface{}{}
	ServiceInfo[""] = ""
	_, _, _, statusCode = postHTTPDataByRfAPI(deviceIPAddress, RfLogService+"Actions/LogService.Reset", token, ServiceInfo)
	if statusCode != http.StatusOK {
		logrus.Errorf("Failed to reset log data to device %s, status code %d", deviceIPAddress, statusCode)
		return statusCode, errors.New("Failed to reset log data to device " + deviceIPAddress)
	}
	return statusCode, nil
}

func (s *Server) getDeviceLogData(deviceIPAddress string, token string) (retData []string, statusCode int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user account " + userName + " is not available in deivce")
	}
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	dataSlice := []string{}
	httpData, _, statusCode := getHTTPBodyDataByRfAPI(deviceIPAddress, RfLogService+"Entries", token)
	if statusCode != http.StatusOK || httpData == nil {
		logrus.Errorf("Failed to get device data, status code %d", statusCode)
		return nil, statusCode, errors.New("Failed to get device data")
	}
	var jsonData []byte
	jsonData, err = json.Marshal(httpData)
	if err != nil {
		return nil, http.StatusInternalServerError, errors.New("HTTP Data update error !")
	}
	dataSlice = append(dataSlice, string(jsonData))
	return dataSlice, statusCode, nil
}
