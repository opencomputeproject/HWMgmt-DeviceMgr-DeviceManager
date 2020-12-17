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
	"strconv"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

//RfDeviceSystem
const RfDeviceSystem = "/redfish/v1/Systems/1/"

//RfSystemGrubDefault
const RfSystemGrubDefault = "/redfish/v1/Systems/1/Actions/ComputerSystem.GrubDefault/"

//RfSystem
const RfSystem = "/redfish/v1/Systems/"

//RfDeviceSystemReset
const RfDeviceSystemReset = RfSystem + "1/Actions/ComputerSystem.Reset/"

//RfOpenBmcDeviceSystemReset
const RfOpenBmcDeviceSystemReset = RfSystem + "system/Actions/ComputerSystem.Reset/"

//RfChassis
const RfChassis = "/redfish/v1/Chassis/"

//RfDeviceTemperature
const RfDeviceTemperature = RfChassis + "1/Thermal/"

//RfOpenBmcTemperature
const RfOpenBmcTemperature = RfChassis + "chassis/Thermal"

func (s *Server) getDeviceBootData(deviceIPAddress string, token string) (grubDefault []string, statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	grubDefault = s.getDeviceData(deviceIPAddress, RfDeviceSystem, token, 6, "GrubDefault@Redfish.AllowableValues")
	if grubDefault == nil {
		logrus.Errorf("Failed to get the Grub boot data!")
		return nil, http.StatusNotFound, errors.New("Failed to get the Grub boot data!")
	}
	return grubDefault, http.StatusOK, nil
}

func (s *Server) getDeviceDefaultBoot(deviceIPAddress string, token string) (defaultBoot []string, statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	defaultBoot = s.getDeviceData(deviceIPAddress, RfDeviceSystem, token, 4, "GrubDefault")
	if defaultBoot == nil {
		logrus.Errorf("Failed to get the Grub default boot!")
		return nil, http.StatusNotFound, errors.New("Failed to get the Grub default boot!")
	}
	return defaultBoot, http.StatusOK, nil
}

func (s *Server) setDeviceDefaultBoot(deviceIPAddress string, token string, defaultBoot string) (statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != s.getDefineUserPrivilege(deviceIPAddress)[0] {
		logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege is not administrator")
	}
	if len(defaultBoot) == 0 {
		logrus.Errorf("The device boot option is empty")
		return http.StatusBadRequest, errors.New("The device boot option is empty")
	}
	grubDefault := s.getDeviceData(deviceIPAddress, RfDeviceSystem, token, 6, "GrubDefault@Redfish.AllowableValues")
	var found bool = false
	for _, option := range grubDefault {
		if option == defaultBoot {
			found = true
			break
		}
	}
	if found == false {
		logrus.Errorf("The device boot option (%s) does not support", defaultBoot)
		return http.StatusBadRequest, errors.New("The device boot option (" + defaultBoot + ") does not support")
	}
	deviceBootInfo := map[string]interface{}{}
	deviceBootInfo["GrubDefault"] = defaultBoot
	_, _, _, statusCode := postHTTPDataByRfAPI(deviceIPAddress, RfSystemGrubDefault, token, deviceBootInfo)
	switch statusCode {
	case http.StatusServiceUnavailable:
		logrus.Errorf("The device %s system does not support UEFI environment", deviceIPAddress)
		return statusCode, errors.New("The device " + deviceIPAddress + " does not support UEFI environment")
	case http.StatusBadRequest:
		logrus.Errorf("The device boot option (%s) is invalid", defaultBoot)
		return statusCode, errors.New("The device boot option (" + defaultBoot + ") is invalid")
	case http.StatusOK:
		logrus.Infof("The device boot option (%s) sent to device successfully", defaultBoot)
		return statusCode, errors.New("The device boot option (" + defaultBoot + ") sent to device successfully")
	default:
		logrus.Errorf("Unkown HTTP status code %d", statusCode)
	}
	return statusCode, nil
}

func (s *Server) resetDeviceSystem(deviceIPAddress string, token string, resetType string) (statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != s.getDefineUserPrivilege(deviceIPAddress)[0] {
		logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege is not administrator")
	}
	if len(resetType) == 0 {
		logrus.Errorf("The device system reset type is empty")
		return http.StatusBadRequest, errors.New("The device system reset type is empty")
	}
	if resetType != "GracefulRestart" && resetType != "GracefulShutdown" {
		logrus.Errorf("The is wrong reset type %s, It should be \"GracefulRestart/GracefulShutdown\"", resetType)
		return http.StatusBadRequest, errors.New("The is wrong reset type " + resetType + ", It should be \"GracefulRestart/GracefulShutdown\"")
	}
	resetdeviceInfo := map[string]interface{}{}
	resetdeviceInfo["ResetType"] = resetType
	var deviceRedfish = []string{RfDeviceSystemReset, RfOpenBmcDeviceSystemReset}
	deviceRF, _ := s.getRedfishAPI(deviceIPAddress, deviceRedfish)
	_, _, _, statusCode := postHTTPDataByRfAPI(deviceIPAddress, deviceRF, token, resetdeviceInfo)
	if statusCode != http.StatusOK {
		logrus.Errorf("Failed to reset system to device %s, status code %d", deviceIPAddress, statusCode)
		return statusCode, errors.New("Failed to reset system to device " + deviceIPAddress)
	}
	return statusCode, nil
}

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
	var deviceRedfish = []string{RfDeviceTemperature, RfOpenBmcTemperature}
	deviceRF, id := s.getRedfishAPI(deviceIPAddress, deviceRedfish)
	tempData, _, statusCode := getHTTPBodyDataByRfAPI(deviceIPAddress, deviceRF, token)
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
		if id == 0 || id == 255 {
			if (okValue&0x20 == 0) && dataStr == "UpperThresholdFatal" {
				mapData["UpperThresholdFatal"] = dataStr1
				okValue = okValue | 0x20
			}
		} else if id == 1 {
			if (okValue&0x20 == 0) && dataStr == "LowerThresholdCritical" {
				mapData["LowerThresholdCritical"] = dataStr1
				okValue = okValue | 0x20
			}
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

func (s *Server) setDeviceTemperatureForEvent(deviceIPAddress string, token string, memberId string, upperThresholdNonCritical uint32, lowerThresholdNonCritical uint32) (statusCode int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	privilege := s.getDefineUserPrivilege(deviceIPAddress)
	if userPrivilege == privilege[2] {
		logrus.Errorf("The user %s privilege (%s) could not configure temperature event to this device %s", userName, privilege[2], deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege (" + privilege[2] + ") could not configure temperature event")
	}
	if upperThresholdNonCritical <= lowerThresholdNonCritical {
		logrus.Errorf("The lowerThresholdNonCritical (%d) could not configure greater than upperThresholdNonCritical (%d)",
			lowerThresholdNonCritical, upperThresholdNonCritical)
		return http.StatusBadRequest, errors.New("The lowerThresholdNonCritical (" + strconv.FormatUint(uint64(lowerThresholdNonCritical), 10) +
			") could not configure greater than upperThresholdNonCritical (" + strconv.FormatUint(uint64(upperThresholdNonCritical), 10) + ")")
	}
	var TempMap map[string]interface{}
	jsonBody := []byte(`{"Temperatures":{"MemberId": "1", "UpperThresholdNonCritical":  0, "LowerThresholdNonCritical": 0}}`)
	err = json.Unmarshal(jsonBody, &TempMap)
	if err != nil {
		logrus.Errorf("Error Unmarshal %s", err)
		return http.StatusInternalServerError, nil
	}
	DataMap := TempMap["Temperatures"].(map[string]interface{})
	DataMap["MemberId"] = memberId
	DataMap["UpperThresholdNonCritical"] = upperThresholdNonCritical
	DataMap["LowerThresholdNonCritical"] = lowerThresholdNonCritical
	var deviceRedfish = []string{RfDeviceTemperature, RfOpenBmcTemperature}
	deviceRF, _ := s.getRedfishAPI(deviceIPAddress, deviceRedfish)
	_, _, _, statusCode = patchHTTPDataByRfAPI(deviceIPAddress, deviceRF, token, TempMap)
	switch statusCode {
	case http.StatusBadRequest:
		logrus.Errorf("The device event temperature is invalid")
		return statusCode, errors.New("The device event temperature is invalid")
	case http.StatusOK:
		logrus.Infof("The device event temperature sent to device successfully")
		return statusCode, errors.New("The device event temperature sent to device successfully")
	default:
		logrus.Errorf("Failed to configure device event temperature to device %s, status code %d", deviceIPAddress, statusCode)
	}
	return statusCode, nil
}

func (s *Server) getManagerModel(deviceIPAddress string, token string) (model string) {
	psmeModel := strings.Join(s.getDeviceData(deviceIPAddress, RfManager+"1", token, 1, "Model"), " ")
	openbmcModel := strings.Join(s.getDeviceData(deviceIPAddress, RfManager+"bmc", token, 1, "Model"), " ")
	if len(psmeModel) != 0 && psmeModel == RedfishPSMEModel {
		model = psmeModel
	} else if len(openbmcModel) != 0 && openbmcModel == OpenBmcModel {
		model = openbmcModel
	} else {
		model = "unknown model"
	}
	return model
}

func (s *Server) getRedfishModel(deviceIPAddress string, token string) (model string, statusCode int, err error) {
	if len(token) != 0 {
		userName := s.getUserByToken(deviceIPAddress, token)
		if s.getLoginStatus(deviceIPAddress, token, userName) == false {
			logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
			return "", http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
		}
		if s.getUserStatus(deviceIPAddress, token, userName) == false {
			logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
			return "", http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
		}
	}
	return s.getManagerModel(deviceIPAddress, token), http.StatusOK, nil
}

func (s *Server) getCpuUsage(deviceIPAddress string, token string) (retData []string, statusCode int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	cpuStatus := s.getDeviceData(deviceIPAddress, RfDeviceSystem, token, 4, "CpuStatus")
	if cpuStatus == nil {
		logrus.Errorf("Failed to get the CPU status!")
		return nil, http.StatusNotFound, errors.New("Failed to get the CPU status!")
	}
	return cpuStatus, http.StatusOK, nil
}

func (s *Server) setCpuUsageForEvent(deviceIPAddress string, token string, upperThresholdNonCritical uint32) (statusCode int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	privilege := s.getDefineUserPrivilege(deviceIPAddress)
	if userPrivilege == privilege[2] {
		logrus.Errorf("The user %s privilege (%s) could not configure CPU usage event to this device %s", userName, privilege[2], deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege (" + privilege[2] + ") could not configure CPU Usage event")
	}
	if upperThresholdNonCritical <= 0 || upperThresholdNonCritical >= 100 {
		logrus.Errorf("The upperThresholdNonCritical could only configure 0~100")
		return http.StatusBadRequest, errors.New("The upperThresholdNonCritical could only configure 0~100")
	}
	var cpuUsageMap map[string]interface{}
	jsonBody := []byte(`{"CpuStatus":{"UpperThresholdNonCritical":  0}}`)
	err = json.Unmarshal(jsonBody, &cpuUsageMap)
	if err != nil {
		logrus.Errorf("Error Unmarshal %s", err)
		return http.StatusInternalServerError, nil
	}
	DataMap := cpuUsageMap["CpuStatus"].(map[string]interface{})
	DataMap["UpperThresholdNonCritical"] = upperThresholdNonCritical
	_, _, _, statusCode = patchHTTPDataByRfAPI(deviceIPAddress, RfDeviceSystem, token, cpuUsageMap)
	switch statusCode {
	case http.StatusBadRequest:
		logrus.Errorf("The device CPU usage is invalid")
		return statusCode, errors.New("The device CPU usage is invalid")
	case http.StatusOK:
		logrus.Infof("The device CPU usage sent to device successfully")
		return statusCode, errors.New("The device CPU usage sent to device successfully")
	default:
		logrus.Errorf("Failed to configure device CPU usage to device %s, status code %d", deviceIPAddress, statusCode)
	}
	return statusCode, nil
}
