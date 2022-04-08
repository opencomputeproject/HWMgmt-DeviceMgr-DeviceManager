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
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

const (
	//RfChassis ...
	RfChassis = "/redfish/v1/Chassis/"
)

func (s *Server) getDeviceSupportedResetType(deviceIPAddress, authStr string) (deviceResetType []string, statusCode int, err error) {
	var resetTypeAllowValue []string
	chassisOdataIds, _, _ := s.getDeviceData(deviceIPAddress, RfChassis, authStr, 2, "@odata.id")
	for _, chassisOdataID := range chassisOdataIds {
		resetTypeAllowValue, _, _ = s.getDeviceData(deviceIPAddress, chassisOdataID, authStr, 3, "ResetType@Redfish.AllowableValues")
		if resetTypeAllowValue == nil {
			logrus.Errorf(ErrGetResetTypeFailed.String())
			return nil, http.StatusNotFound, errors.New(ErrGetResetTypeFailed.String())
		}
	}
	return resetTypeAllowValue, http.StatusOK, nil
}

func (s *Server) resetDeviceSystem(deviceIPAddress, authStr, resetType string) (statusNum int, err error) {
	if len(resetType) == 0 {
		logrus.Errorf(ErrResetTypeEmpty.String())
		return http.StatusBadRequest, errors.New(ErrResetTypeEmpty.String())
	}
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	chassisOdataIds, _, _ := s.getDeviceData(deviceIPAddress, RfChassis, authStr, 2, "@odata.id")
	for _, chassisOdataID := range chassisOdataIds {
		resetTypeAllowValue, _, _ := s.getDeviceData(deviceIPAddress, chassisOdataID, authStr, 3, "ResetType@Redfish.AllowableValues")
		var found bool
		found = false
		for _, option := range resetTypeAllowValue {
			if option == resetType {
				found = true
				break
			}
		}
		if found == false {
			logrus.Errorf(ErrResetTypeNotsupport.String(resetType, strings.Join(resetTypeAllowValue, " ")))
			return http.StatusBadRequest, errors.New(ErrResetTypeNotsupport.String(resetType, strings.Join(resetTypeAllowValue, " ")))
		}
		resetdeviceInfo := map[string]interface{}{}
		resetdeviceInfo["ResetType"] = resetType
		_, _, statusNum, _ = postHTTPDataByRfAPI(deviceIPAddress, chassisOdataID+"/Actions/Chassis.Reset", userAuthData, resetdeviceInfo)
		if statusNum != http.StatusOK {
			logrus.Errorf(ErrResetSystemFailed.String(strconv.Itoa(statusNum)))
			return statusNum, errors.New(ErrResetSystemFailed.String(strconv.Itoa(statusNum)))
		}
	}
	return statusNum, nil
}

func (s *Server) getDeviceTemperature(deviceIPAddress, authStr string) (retData []string, statusCode int, err error) {
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return nil, http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	mapData := make(map[string]interface{})
	dataSlice := []string{}
	chassisOdataIds, _, _ := s.getDeviceData(deviceIPAddress, RfChassis, authStr, 2, "@odata.id")
	for _, chassisOdataID := range chassisOdataIds {
		tempData, statusCode, _ := getHTTPBodyDataByRfAPI(deviceIPAddress, chassisOdataID+"/Thermal", userAuthData)
		if tempData == nil {
			logrus.Errorf(ErrGetTemperDataFailed.String())
			return nil, statusCode, errors.New(ErrGetTemperDataFailed.String())
		}
		dataTemp := JSONToByte(tempData["Temperatures"])
		if dataTemp == nil {
			logrus.Errorf(ErrConvertTemperDataFailed.String())
			return nil, http.StatusNoContent, errors.New(ErrConvertTemperDataFailed.String())
		}
		var okValue int
		okValue = 0x0
		for _, value := range dataTemp {
			dataTemp1 := bytes.Split(value, []byte(":"))
			if len(dataTemp1) == 0 {
				continue
			}
			dataStr := string(dataTemp1[0])
			dataStr1 := string(dataTemp1[1])
			if (okValue&0x1 == 0) && dataStr == "Name" {
				mapData["Name"] = dataStr1
				okValue = okValue | 0x1
			}
			if (okValue&0x2 == 0) && dataStr == "MemberId" {
				mapData["MemberId"] = dataStr1
				okValue = okValue | 0x2
			}
			if (okValue&0x4 == 0) && dataStr == "LowerThresholdNonCritical" {
				mapData["LowerThresholdNonCritical"] = dataStr1
				okValue = okValue | 0x4
			}
			if (okValue&0x8 == 0) && dataStr == "UpperThresholdNonCritical" {
				mapData["UpperThresholdNonCritical"] = dataStr1
				okValue = okValue | 0x8
			}
			if (okValue&0x10 == 0) && dataStr == "UpperThresholdCritical" {
				mapData["UpperThresholdCritical"] = dataStr1
				okValue = okValue | 0x10
			}
			if (okValue&0x20 == 0) && dataStr == "UpperThresholdFatal" {
				mapData["UpperThresholdFatal"] = dataStr1
				okValue = okValue | 0x20
			}
			if (okValue&0x40 == 0) && dataStr == "ReadingCelsius" {
				mapData["ReadingCelsius"] = dataStr1
				okValue = okValue | 0x40
			}
			if okValue == 0x7f {
				dataByte, err := json.Marshal(mapData)
				if err != nil {
					logrus.Errorf("Failed to convert data")
					return nil, statusCode, errors.New("Failed to convert data")
				}
				dataSlice = append(dataSlice, string(dataByte))
				okValue = 0x0
			}
		}
	}
	return dataSlice, statusCode, nil
}

//setDeviceTemperatureForEvent ...
func (s *Server) setDeviceTemperatureForEvent(deviceIPAddress, authStr, memberID string, upperThresholdNonCritical uint32, lowerThresholdNonCritical uint32) (statusCode int, err error) {
	if upperThresholdNonCritical <= lowerThresholdNonCritical {
		logrus.Errorf("The lowerThresholdNonCritical (%d) could not configure greater than upperThresholdNonCritical (%d)",
			lowerThresholdNonCritical, upperThresholdNonCritical)
		return http.StatusBadRequest, errors.New("The lowerThresholdNonCritical (" + strconv.FormatUint(uint64(lowerThresholdNonCritical), 10) +
			") could not configure greater than upperThresholdNonCritical (" + strconv.FormatUint(uint64(upperThresholdNonCritical), 10) + ")")
	}
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	var TempMap map[string]interface{}
	jsonBody := []byte(`{"Temperatures":{"MemberId": "1", "UpperThresholdNonCritical":  0, "LowerThresholdNonCritical": 0}}`)
	err = json.Unmarshal(jsonBody, &TempMap)
	if err != nil {
		logrus.Errorf("Error Unmarshal %s", err)
		return http.StatusInternalServerError, nil
	}
	DataMap := TempMap["Temperatures"].(map[string]interface{})
	DataMap["MemberId"] = memberID
	DataMap["UpperThresholdNonCritical"] = upperThresholdNonCritical
	DataMap["LowerThresholdNonCritical"] = lowerThresholdNonCritical
	chassisOdataIds, _, _ := s.getDeviceData(deviceIPAddress, RfChassis, authStr, 2, "@odata.id")
	for _, chassisOdataID := range chassisOdataIds {
		_, _, statusCode, _ = patchHTTPDataByRfAPI(deviceIPAddress, chassisOdataID+"/Thermal", userAuthData, TempMap)
		switch statusCode {
		case http.StatusBadRequest:
			logrus.Errorf(ErrEventTemperInvalid.String())
			return statusCode, errors.New(ErrEventTemperInvalid.String())
		case http.StatusOK:
			logrus.Infof("The device event temperature sent to device successfully")
			return statusCode, nil
		default:
			logrus.Errorf(ErrSetEventTemperFailed.String(strconv.Itoa(statusCode)))
			return statusCode, errors.New(ErrSetEventTemperFailed.String(strconv.Itoa(statusCode)))
		}
	}
	return
}
