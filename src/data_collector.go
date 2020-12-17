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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	logrus "github.com/sirupsen/logrus"
)

func addTimestampToDeviceData(deviceData map[string]interface{}) (retData []string, StatusNum int, err error) {
	dataSlice := []string{}
	if deviceData != nil {
		var jsonData []byte
		jsonData, err = json.Marshal(deviceData)
		if err != nil {
			return nil, http.StatusInternalServerError, errors.New("HTTP Data update error !")
		}
		nowTime := time.Now()
		jsonData = jsonData[1:]
		dataSlice = append(dataSlice, "{\"DataTimestamp\":\""+nowTime.Format("01-02-2006 15:04:05")+"\","+string(jsonData))
		err = json.Unmarshal([]byte(dataSlice[0]), &deviceData)
		if err != nil {
			return nil, http.StatusInternalServerError, errors.New("The data slice is incorrect !")
		}
	} else {
		return nil, http.StatusNoContent, errors.New("Device data is empty !")
	}
	return dataSlice, http.StatusOK, nil
}

func valueConvertToString(inValue interface{}) (outValue []string) {
	switch inValue.(type) {
	case string:
		outValue = append(outValue, inValue.(string))
	case int64:
		outValue = append(outValue, strconv.FormatInt(inValue.(int64), 10))
	case float64:
		outValue = append(outValue, strconv.FormatFloat(inValue.(float64), 'g', -1, 64))
	case bool:
		outValue = append(outValue, strconv.FormatBool(inValue.(bool)))
	case map[string]interface{}:
		outValue = append(outValue, fmt.Sprintln(inValue))
	case []interface{}:
		outValue = append(outValue, fmt.Sprintln(inValue))
	}
	return outValue
}

/* parseMap() parses the json structure, amap, and returns all sub-folder paths found at the 2nd level of the multiplayer structure
 */
func parseMap(amap map[string]interface{}, level uint, levelPos uint, archive map[string]bool, keyword string) (paths []string) {
	level = level + 1
	for key, val := range amap {
		switch v := val.(type) {
		case map[string]interface{}:
			if level == levelPos && key == keyword {
				data, err := json.Marshal(val)
				if err == nil {
					paths = append(paths, string(data))
				}
			} else {
				p := parseMap(v, level, levelPos, archive, keyword)
				paths = append(paths, p...)
			}
		case []interface{}:
			if level == levelPos && key == keyword {
				for _, name := range val.([]interface{}) {
					paths = append(paths, name.(string))
				}
			} else {
				p := parseArray(v, level, levelPos, archive, keyword)
				paths = append(paths, p...)
			}
		default:
			if level == levelPos && key == keyword {
				/* sub-folder path of a resource can be found as the value of the key '@odata.id' showing up at the 2nd level of the data read from a resource. When a path is found, it's checked against the array 'archive' to avoid duplicates. */
				data := valueConvertToString(val)
				for _, name := range data {
					if _, ok := archive[name]; !ok {
						archive[name] = true
						paths = append(paths, name)
					}
				}
			}
		}
	}
	return paths
}

/* parseArray() parses any vlaue, if in the form of an array, of a key-value pair found in the json structure, and returns any paths found.
 */
func parseArray(anarray []interface{}, level uint, levelPos uint, archive map[string]bool, keyword string) (paths []string) {
	for _, val := range anarray {
		switch v := val.(type) {
		case map[string]interface{}:
			p := parseMap(v, level, levelPos, archive, keyword)
			paths = append(paths, p...)
		}
	}
	return paths
}

/* readDeviceResource() reads data from the specified Redfish resource, including its sub-folders, of the specified device ip and rerutnrs the data read.

Based on careful examination of the data returned from several resources sampled, it was determined that sub-folder paths can be found as the value to the key '@odata.id' showing up at the 2nd level of the data read from a resource.
*/
func readDeviceResource(deviceIPAddress string, resource string, archive map[string]bool, token string) (data []string) {
	body, err, statusCode := getHTTPBodyByRfAPI(deviceIPAddress, resource, token)
	if err != nil {
		logrus.Errorf("Failed to get the HTTP body %s, status code %d", err, statusCode)
		return
	}

	fmt.Println(string(body))
	data = append(data, string(body))

	m := map[string]interface{}{}
	err = json.Unmarshal([]byte(body), &m)
	if err != nil {
		logrus.Errorf("Error Unmarshal %s", err)
		return
	}
	resources := parseMap(m, 0, 2, archive, "@odata.id")
	for _, resource := range resources {
		d := readDeviceResource(deviceIPAddress, resource, archive, token)
		data = append(data, d...)
	}
	return data
}

/* sample JSON files can be found in the samples folder */
func (s *Server) getDeviceDataByResource(deviceIPAddress string, resource string, userName string) (data []string) {
	token := s.getTokenByUser(deviceIPAddress, userName)
	archive := make(map[string]bool)
	/* 'archive' maintains a list of all resources that will be/have been visited to avoid duplicates */
	archive[resource] = true
	data = readDeviceResource(deviceIPAddress, resource, archive, token)
	return data
}

func (s *Server) getDataFromCache(deviceDataFile *os.File, RfAPI string) (statusNum int, retData []string, err error) {
	var deviceData map[string]interface{}
	var found bool
	retData = nil
	_, err = deviceDataFile.Seek(0, 0)
	if err != nil {
		logrus.Errorf("err Seek %s", err)
		return http.StatusNoContent, retData, errors.New("Device data file could not move to 0 position")
	}
	found = false
	scanner := bufio.NewScanner(deviceDataFile)
	for scanner.Scan() {
		strData := scanner.Text()
		err := json.Unmarshal([]byte(strData), &deviceData)
		if err != nil {
			logrus.Errorf("Unmarshal %s", err)
			break
		}
		deviceAPIData := s.getRedfishDeviceData(deviceData, "", 1, "@odata.id")
		if deviceAPIData != nil {
			if strings.EqualFold(strings.Join(deviceAPIData, " "), RfAPI) {
				retData = append(retData, strData)
				found = true
			}
		}
	}
	if found != true {
		return http.StatusNotFound, retData, errors.New("The Redfish API does not exist in the data cache")
	}
	return http.StatusOK, retData, nil
}

func (s *Server) getDeviceDataByFileData(deviceIPAddress string, token string, RfAPI string) (statusNum int, retData []string, err error) {
	retData = nil
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, retData, errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, retData, errors.New("The user account " + userName + " is not available in deivce")
	}
	deviceDataFile := s.devicemap[deviceIPAddress].DeviceDatafile
	if deviceDataFile == nil {
		logrus.Errorf("Device data file not found (%s)", deviceIPAddress)
		return http.StatusNotFound, retData, errors.New("Device data file not found (" + deviceIPAddress + ")")
	}
	s.devicemap[deviceIPAddress].DeviceDataLockFile.Lock()
	statusNum, retData, err = s.getDataFromCache(deviceDataFile, RfAPI)
	s.devicemap[deviceIPAddress].DeviceDataLockFile.Unlock()
	return http.StatusOK, retData, nil
}

func (s *Server) genericDeviceAccess(deviceIPAddress string, RfAPI string, token string, httpMethod string, httpPostData map[string]interface{}, httpDeleteData string, httpPatchData map[string]interface{}) (statusCode int, retData map[string]interface{}, err error) {
	logrus.Info("Received genericDeviceAccess")
	var httpData map[string]interface{}
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, httpData, errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, httpData, errors.New("The user account " + userName + " is not available in deivce")
	}
	switch httpMethod {
	case "GET":
		httpData, _, statusCode = getHTTPBodyDataByRfAPI(deviceIPAddress, RfAPI, token)
		if statusCode != http.StatusOK {
			logrus.Errorf("Failed to get device data, status code %d", statusCode)
			return http.StatusNotFound, httpData, errors.New("Failed to get device data")
		}
	case "POST":
		_, httpData, _, statusCode = postHTTPDataByRfAPI(deviceIPAddress, RfAPI, token, httpPostData)
		if statusCode != http.StatusOK && statusCode != http.StatusCreated {
			logrus.Errorf("Failed to post data to device, status code %d", statusCode)
			return statusCode, httpData, errors.New("Failed to post data to device")
		}
	case "DELETE":
		_, _, statusCode = deleteHTTPDataByRfAPI(deviceIPAddress, RfAPI, token, httpDeleteData)
		if statusCode != http.StatusOK {
			logrus.Errorf("Failed to delete device data, status code %d, delete data %s", statusCode, httpDeleteData)
			return statusCode, httpData, errors.New("Failed to delete device data")
		}
	case "PATCH":
		_, httpData, _, statusCode = patchHTTPDataByRfAPI(deviceIPAddress, RfAPI, token, httpPatchData)
		if statusCode != http.StatusOK {
			logrus.Errorf("Failed to patch device data, status code %d, delete data %s", statusCode, httpPatchData)
			return statusCode, httpData, errors.New("Failed to patch device data")
		}
	default:
		logrus.Errorf("Unsupported HTTP method %s", httpMethod)
		return http.StatusUnsupportedMediaType, httpData, errors.New("Unsupported HTTP method")
	}
	return http.StatusOK, httpData, nil
}
