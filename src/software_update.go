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
	"errors"
	"net/http"
	"strconv"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

var (
	//softwareUpdateType ...
	softwareUpdateType = [...]string{"MU", "NOS", "PACKAGE"}
)

const (
	//RfMultipleUpdater ...
	RfMultipleUpdater = "/redfish/v1/UpdateService/FirmwareInventory/MU"
	//RfNOSUpdate ...
	RfNOSUpdate = "/redfish/v1/UpdateService/FirmwareInventory/NOS"
	//RfPackageUpdate
	RfPackageUpdate = "/redfish/v1/UpdateService/SoftwareInventory/PACKAGE"
)

func (s *Server) sendDeviceSoftwareDownloadURI(deviceIPAddress, authStr, softwareType, URI string) (statusCode int, err error) {
	if len(URI) == 0 {
		logrus.Errorf("The URI is empty")
		return http.StatusBadRequest, errors.New("The URI is empty")
	}
	httpStr := strings.Split(URI, ":")
	if httpStr != nil && httpStr[0] != "http" && httpStr[0] != "https" && httpStr[0] != "tftp" {
		logrus.Errorf("The URI format is wrong")
		return http.StatusBadRequest, errors.New("The URI format is wrong")
	}
	if len(softwareType) == 0 {
		logrus.Errorf(ErrSWTypeEmpty.String())
		return http.StatusBadRequest, errors.New(ErrSWTypeEmpty.String())
	}
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	var softwareUpdateRfAPI string
	switch softwareType {
	case softwareUpdateType[0]:
		softwareUpdateRfAPI = RfMultipleUpdater
	case softwareUpdateType[1]:
		softwareUpdateRfAPI = RfNOSUpdate
	case softwareUpdateType[2]:
		softwareUpdateRfAPI = RfPackageUpdate
	default:
		logrus.Errorf(ErrSWTypeInvalid.String())
		return http.StatusBadRequest, errors.New(ErrSWTypeInvalid.String())
	}
	ServiceInfo := map[string]interface{}{}
	body := map[string]interface{}{}
	ServiceInfo["ImageURI"] = URI
	_, body, statusCode, _ = postHTTPDataByRfAPI(deviceIPAddress, softwareUpdateRfAPI, userAuthData, ServiceInfo)
	switch statusCode {
	case http.StatusServiceUnavailable:
		logrus.Errorf(ErrNotsupportUEFI.String())
		return statusCode, errors.New(ErrNotsupportUEFI.String())
	case http.StatusInsufficientStorage:
		logrus.Errorf(ErrNotsufficientMemStorage.String())
		return statusCode, errors.New(ErrNotsufficientMemStorage.String())
	case http.StatusForbidden:
		logrus.Errorf(ErrSWUpdateInProcess.String())
		return statusCode, errors.New(ErrSWUpdateInProcess.String())
	case http.StatusNotImplemented:
		logrus.Errorf(ErrSWUpdateNotImplemented.String())
		return statusCode, errors.New(ErrSWUpdateNotImplemented.String())
	case http.StatusOK:
		var updateState string
		softwareUpdateState := s.getRedfishDeviceData(body, 1, "UpdateState")
		if softwareUpdateState != nil {
			updateState = strings.Join(softwareUpdateState, " ")
		}
		logrus.Infof("The device %s is %s status now", deviceIPAddress, updateState)
		return statusCode, nil
	default:
		logrus.Errorf(ErrUnsupportHTTPStateCode.String(strconv.Itoa(statusCode)))
		return statusCode, errors.New(ErrUnsupportHTTPStateCode.String(strconv.Itoa(statusCode)))
	}
}
