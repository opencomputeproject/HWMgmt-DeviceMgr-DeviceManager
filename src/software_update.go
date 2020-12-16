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
	"errors"
	"net/http"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

var softwareUpdateType = [...]string{"MU", "NOS"}

const RfMultipleUpdater = "/redfish/v1/UpdateService/FirmwareInventory/MU"
const RfNOSUpdate = "/redfish/v1/UpdateService/FirmwareInventory/NOS"

func (s *Server) sendDeviceSoftwareDownloadURI(deviceIPAddress string, token string, softwareType string, URI string) (statusCode int, err error) {
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
	privilege := s.getDefineUserPrivilege(deviceIPAddress)
	if userPrivilege != privilege[0] && userPrivilege != privilege[1] {
		logrus.Errorf("The user %s privilege could not change Log sevice state from this device %s", deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user privilege could not change state from  this device")
	}
	if len(URI) == 0 {
		logrus.Errorf("The URI is empty !")
		return http.StatusBadRequest, errors.New("The URI is empty !")
	}
	httpStr := strings.Split(URI, ":")
	if httpStr != nil && httpStr[0] != "http" && httpStr[0] != "https" && httpStr[0] != "tftp" {
		logrus.Errorf("The URI format is wrong !")
		return http.StatusBadRequest, errors.New("The URI format is wrong !")
	}
	if len(softwareType) == 0 {
		logrus.Errorf("The software update type is empty !")
		return http.StatusBadRequest, errors.New("The software update type is empty !")
	}
	var softwareUpdateRfAPI string
	switch softwareType {
	case softwareUpdateType[0]:
		softwareUpdateRfAPI = RfMultipleUpdater
	case softwareUpdateType[1]:
		softwareUpdateRfAPI = RfNOSUpdate
	default:
		logrus.Errorf("The software update type is invalid")
		return http.StatusBadRequest, errors.New("The software update type is invalid")
	}
	ServiceInfo := map[string]interface{}{}
	body := map[string]interface{}{}
	ServiceInfo["ImageURI"] = URI
	_, body, _, statusCode = postHTTPDataByRfAPI(deviceIPAddress, softwareUpdateRfAPI, token, ServiceInfo)
	switch statusCode {
	case http.StatusServiceUnavailable:
		logrus.Errorf("The device %s system does not support UEFI environment", deviceIPAddress)
		return statusCode, errors.New("The device " + deviceIPAddress + " does not support UEFI environment")
	case http.StatusInsufficientStorage:
		logrus.Errorf("The device %s system does not have sufficient Memory/Storage", deviceIPAddress)
		return statusCode, errors.New("The device " + deviceIPAddress + " does not have sufficient Memory/Storage")
	case http.StatusForbidden:
		logrus.Errorf("The update request is processing, This is forbidden to request again", deviceIPAddress)
		return statusCode, errors.New("The update request is processing, This is forbidden to request again")
	case http.StatusOK:
		var updateState string
		softwareUpdateState := s.getRedfishDeviceData(body, "", 1, "UpdateState")
		if softwareUpdateState != nil {
			updateState = strings.Join(softwareUpdateState, " ")
		}
		logrus.Infof("The device %s is %s status now", deviceIPAddress, updateState)
		return statusCode, errors.New("The device " + deviceIPAddress + " is " + updateState + " status now")
	default:
		logrus.Errorf("Unkown HTTP status code %d", statusCode)
	}
	return statusCode, nil
}
