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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

var bfound bool = false

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
func parseMap(amap map[string]interface{}, level uint, levelPos uint, archive map[string]bool, keyword string) (paths []string, found bool) {
	level = level + 1
	for key, val := range amap {
		switch v := val.(type) {
		case map[string]interface{}:
			if level == levelPos && key == keyword {
				bfound = true
				data, err := json.Marshal(val)
				if err == nil {
					paths = append(paths, string(data))
				}
			} else {
				p, _ := parseMap(v, level, levelPos, archive, keyword)
				paths = append(paths, p...)
			}
		case []interface{}:
			if level == levelPos && key == keyword {
				bfound = true
				for _, name := range val.([]interface{}) {
					if reflect.TypeOf(name).Kind() == reflect.Map {
						data, err := json.Marshal(val)
						if err == nil {
							paths = append(paths, string(data))
						}
					} else if reflect.TypeOf(name).Kind() == reflect.String {
						paths = append(paths, name.(string))
					} else {
						p := parseArray(v, level, levelPos, archive, keyword)
						paths = append(paths, p...)
					}
				}
			} else {
				p := parseArray(v, level, levelPos, archive, keyword)
				paths = append(paths, p...)
			}
		default:
			if level == levelPos && key == keyword {
				bfound = true
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
	return paths, bfound
}

/* parseArray() parses any vlaue, if in the form of an array, of a key-value pair found in the json structure, and returns any paths found.
 */
func parseArray(anarray []interface{}, level uint, levelPos uint, archive map[string]bool, keyword string) (paths []string) {
	for _, val := range anarray {
		switch v := val.(type) {
		case map[string]interface{}:
			p, _ := parseMap(v, level, levelPos, archive, keyword)
			paths = append(paths, p...)
		}
	}
	return paths
}

/* readDeviceResource() reads data from the specified Redfish resource, including its sub-folders, of the specified device ip and rerutnrs the data read.

Based on careful examination of the data returned from several resources sampled, it was determined that sub-folder paths can be found as the value to the key '@odata.id' showing up at the 2nd level of the data read from a resource.
*/
func readDeviceResource(deviceIPAddress, resource string, archive map[string]bool, userAuthData userAuth) (data []string, err error) {
	body, statusCode, err := getHTTPBodyByRfAPI(deviceIPAddress, resource, userAuthData)
	data = append(data, string(body))
	if err != nil || body == nil {
		logrus.Errorf(ErrHTTPGetBody.String(err.Error(), strconv.Itoa(statusCode)))
		return data, err
	}
	if statusCode == http.StatusOK {
		if len(body) != 0 {
			m := map[string]interface{}{}
			err = json.Unmarshal([]byte(body), &m)
			if err != nil {
				logrus.Errorf(ErrConvertData.String(err.Error()), "body: "+string(body))
			}
		} else {
			logrus.Errorf(ErrHTTPBodyEmpty.String())
			err = errors.New(ErrHTTPBodyEmpty.String())
		}
	} else {
		logrus.Errorf(ErrHTTPGetDataFailed.String(strconv.Itoa(statusCode)))
		err = errors.New(ErrHTTPGetDataFailed.String(strconv.Itoa(statusCode)))
	}
	return data, err
}

func (s *Server) getDeviceDataByResource(deviceIPAddress, resource string, userAuthData userAuth) (data []string, err error) {
	archive := make(map[string]bool)
	/* 'archive' maintains a list of all resources that will be/have been visited to avoid duplicates */
	data, err = readDeviceResource(deviceIPAddress, resource, archive, userAuthData)
	return data, err
}

func (s *Server) getDataFromCache(deviceDataFile *os.File, RfAPI string) (statusNum int, retData []string, err error) {
	var deviceData map[string]interface{}
	var found bool
	retData = nil
	_, err = deviceDataFile.Seek(0, 0)
	if err != nil {
		logrus.Errorf("err Seek %s", err)
		return http.StatusNoContent, retData, errors.New(ErrDataToFirstPos.String())
	}
	found = false
	scanner := bufio.NewScanner(deviceDataFile)
	for scanner.Scan() {
		strData := scanner.Text()
		if len(strData) != 0 {
			err := json.Unmarshal([]byte(strData), &deviceData)
			if err != nil {
				logrus.Errorf("Unmarshal %s", err)
				break
			}
		}
		deviceAPIData := s.getRedfishDeviceData(deviceData, 1, "@odata.id")
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

func (s *Server) getDeviceDataByFileData(deviceIPAddress, RfAPI string) (statusNum int, retData []string, err error) {
	retData = nil
	deviceDataFile := s.devicemap[deviceIPAddress].DeviceDatafile
	if deviceDataFile == nil {
		logrus.Errorf(ErrDeviceDataFileNotFound.String(deviceIPAddress))
		return http.StatusNotFound, retData, errors.New(ErrDeviceDataFileNotFound.String(deviceIPAddress))
	}
	s.devicemap[deviceIPAddress].DeviceDataLockFile.Lock()
	statusNum, retData, err = s.getDataFromCache(deviceDataFile, RfAPI)
	s.devicemap[deviceIPAddress].DeviceDataLockFile.Unlock()
	return http.StatusOK, retData, nil
}

func (s *Server) genericDeviceAccess(deviceIPAddress, RfAPI, authStr string, httpMethod string,
	httpPostData map[string]interface{}, httpDeleteData string, httpPatchData map[string]interface{}) (statusCode int,
	retData map[string]interface{}, err error) {
	logrus.Info("Received genericDeviceAccess")
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, nil, errors.New(ErrUserAuthNotFound.String())
	}
	var httpData map[string]interface{}
	switch httpMethod {
	case "GET":
		httpData, statusCode, _ = getHTTPBodyDataByRfAPI(deviceIPAddress, RfAPI, userAuthData)
		if statusCode != http.StatusOK {
			logrus.Errorf(ErrGetDeviceData.String(strconv.Itoa(statusCode)))
			return statusCode, httpData, errors.New(ErrGetDeviceData.String(strconv.Itoa(statusCode)))
		}
	case "POST":
		_, httpData, statusCode, _ = postHTTPDataByRfAPI(deviceIPAddress, RfAPI, userAuthData, httpPostData)
		if statusCode != http.StatusOK && statusCode != http.StatusCreated {
			logrus.Errorf(ErrPostDeviceData.String(strconv.Itoa(statusCode)))
			return statusCode, httpData, errors.New(ErrPostDeviceData.String(strconv.Itoa(statusCode)))
		}
	case "DELETE":
		_, statusCode, _ = deleteHTTPDataByRfAPI(deviceIPAddress, RfAPI, userAuthData, httpDeleteData)
		if statusCode != http.StatusOK {
			logrus.Errorf(ErrDeleteDeviceData.String(strconv.Itoa(statusCode), httpDeleteData))
			return statusCode, httpData, errors.New(ErrDeleteDeviceData.String(strconv.Itoa(statusCode), httpDeleteData))
		}
	case "PATCH":
		_, httpData, statusCode, _ = patchHTTPDataByRfAPI(deviceIPAddress, RfAPI, userAuthData, httpPatchData)
		var DataStr []string
		if statusCode != http.StatusOK {
			for _, value := range httpPatchData {
				DataStr = append(DataStr, value.(string))
			}
			logrus.Errorf(ErrPatchDeviceData.String(strconv.Itoa(statusCode), strings.Join(DataStr, " ")))
			return statusCode, httpData, errors.New(ErrPatchDeviceData.String(strconv.Itoa(statusCode), strings.Join(DataStr, " ")))
		}
	default:
		logrus.Errorf(ErrUnsupportHTTPMethod.String(httpMethod))
		return http.StatusUnsupportedMediaType, httpData, errors.New(ErrUnsupportHTTPMethod.String(httpMethod))
	}
	return http.StatusOK, httpData, nil
}
