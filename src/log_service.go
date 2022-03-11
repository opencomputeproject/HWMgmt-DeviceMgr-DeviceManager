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
	"strconv"

	logrus "github.com/sirupsen/logrus"
)

const (
	//RfManager ...
	RfManager = "/redfish/v1/Managers/"
)

func (s *Server) checkLogServiceState(deviceIPAddress, authStr, id string) (logService string, state bool) {
	state = false
	managerMembers, _, _ := s.getDeviceData(deviceIPAddress, RfManager, authStr, 2, "@odata.id")
	for _, managerMember := range managerMembers {
		logServices, _, _ := s.getDeviceData(deviceIPAddress, managerMember+"/LogServices", authStr, 2, "@odata.id")
		for _, logService = range logServices {
			logserviceID, _, _ := s.getDeviceData(deviceIPAddress, logService, authStr, 1, "Id")
			if logserviceID[0] == id {
				logState, _, _ := s.getDeviceData(deviceIPAddress, logService, authStr, 1, "ServiceEnabled")
				if logState == nil {
					logrus.Errorf(ErrGetLogServiceStateFailed.String())
					return "", false
				}
				state, _ = strconv.ParseBool(logState[0])
				return logService, state
			}
		}
	}
	return "", state
}

func (s *Server) changeDeviceLogService(deviceIPAddress, authStr, id string, state bool) (statusCode int, err error) {
	logServiceLoc, logState := s.checkLogServiceState(deviceIPAddress, authStr, id)
	if logServiceLoc == "" {
		logrus.Errorf(ErrGetLogServiceRfAPI.String())
		return http.StatusBadRequest, errors.New(ErrGetLogServiceRfAPI.String())
	}
	if logServiceLoc != "" && logState == state {
		logrus.Errorf(ErrLogServiceInTheState.String(strconv.FormatBool(state)))
		return http.StatusBadRequest, errors.New(ErrLogServiceInTheState.String(strconv.FormatBool(state)))
	}
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	ServiceInfo := map[string]interface{}{}
	ServiceInfo["ServiceEnabled"] = state
	_, _, statusCode, _ = patchHTTPDataByRfAPI(deviceIPAddress, logServiceLoc, userAuthData, ServiceInfo)
	if statusCode != http.StatusNoContent && statusCode != http.StatusOK {
		logrus.Errorf(ErrSetLogServiceFailed.String(strconv.Itoa(statusCode)))
		return statusCode, errors.New(ErrSetLogServiceFailed.String(strconv.Itoa(statusCode)))
	}
	return statusCode, nil
}

func (s *Server) resetDeviceLogData(deviceIPAddress, authStr, id string) (statusCode int, err error) {
	logServiceLoc, _ := s.checkLogServiceState(deviceIPAddress, authStr, id)
	if logServiceLoc == "" {
		logrus.Errorf(ErrGetLogServiceRfAPI.String())
		return http.StatusBadRequest, errors.New(ErrGetLogServiceRfAPI.String())
	}
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	ServiceInfo := map[string]interface{}{}
	ServiceInfo[""] = ""
	_, _, statusCode, _ = postHTTPDataByRfAPI(deviceIPAddress, logServiceLoc+"/Actions/LogService.Reset", userAuthData, ServiceInfo)
	if statusCode != http.StatusOK {
		logrus.Errorf(ErrResetLogDataFailed.String(strconv.Itoa(statusCode)))
		return statusCode, errors.New(ErrResetLogDataFailed.String(strconv.Itoa(statusCode)))
	}
	return statusCode, nil
}

func (s *Server) getDeviceLogData(deviceIPAddress, authStr, id string) (retData []string, statusCode int, err error) {
	logServiceLoc, _ := s.checkLogServiceState(deviceIPAddress, authStr, id)
	if logServiceLoc == "" {
		logrus.Errorf(ErrGetLogServiceRfAPI.String())
		return nil, http.StatusBadRequest, errors.New(ErrGetLogServiceRfAPI.String())
	}
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return nil, http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	dataSlice := []string{}
	httpData, statusCode, _ := getHTTPBodyDataByRfAPI(deviceIPAddress, logServiceLoc+"/Entries", userAuthData)
	if statusCode != http.StatusOK || httpData == nil {
		logrus.Errorf(ErrGetDeviceData.String(strconv.Itoa(statusCode)))
		return nil, statusCode, errors.New(ErrGetDeviceData.String(strconv.Itoa(statusCode)))
	}
	var jsonData []byte
	jsonData, err = json.Marshal(httpData)
	if err != nil {
		return nil, http.StatusInternalServerError, errors.New(ErrHTTPDataUpdateFailed.String())
	}
	dataSlice = append(dataSlice, string(jsonData))
	return dataSlice, statusCode, nil
}
