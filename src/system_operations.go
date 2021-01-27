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
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

//RfChassis
const RfChassis = "/redfish/v1/Chassis/"

//RfDeviceTemperature
const RfDeviceTemperature = RfChassis + "1/Thermal/"

func (s *Server) getDeviceTemperature(deviceIPAddress string, token string) (retData []string, statusCode int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	mapData := make(map[string]interface{})
	dataSlice := []string{}
	tempData, _, statusCode := getHTTPBodyDataByRfAPI(deviceIPAddress, RfDeviceTemperature, token)
	if tempData == nil {
		logrus.Errorf("Failed to get device temperature data")
		return nil, statusCode, errors.New("Failed to get device temperature data")
	}
	data, err := json.Marshal(tempData["Temperatures"])
	if err != nil {
		logrus.Errorf("Failed to convert temperature data")
		return nil, http.StatusNoContent, errors.New("Failed to convert temperature data")
	}
	dataTemp := bytes.Split(data, []byte(","))
	var okValue int = 0x0
	for _, value := range dataTemp {
		dataTemp1 := bytes.Split(value, []byte(":"))
		if len(dataTemp1) == 0 {
			continue
		}
		dataStr := strings.Trim(string(dataTemp1[0]), "\"{}[]")
		dataStr1 := strings.Trim(string(dataTemp1[1]), "\"{}[]")
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
		//if id == 0 || id == 255 {
		if (okValue&0x20 == 0) && dataStr == "UpperThresholdFatal" {
			mapData["UpperThresholdFatal"] = dataStr1
			okValue = okValue | 0x20
		}
		if okValue == 0x3f {
			dataByte, err := json.Marshal(mapData)
			if err != nil {
				logrus.Errorf("Failed to convert data")
				return nil, statusCode, errors.New("Failed to convert data")
			}
			dataSlice = append(dataSlice, string(dataByte))
			okValue = 0x0
		}
	}
	return dataSlice, statusCode, nil
}
