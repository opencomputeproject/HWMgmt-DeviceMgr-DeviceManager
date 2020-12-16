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
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	logrus "github.com/sirupsen/logrus"
)

//RfDefaultProtocol  :
const RfDefaultProtocol = "https://"

func getHTTPBodyByRfAPI(deviceIPAddress string, RfAPI string, token string) (body []byte, err error, statusCode int) {
	request, _ := http.NewRequest("GET", RfDefaultProtocol+deviceIPAddress+RfAPI, nil)
	request.Close = true
	if token != "" {
		request.Header.Add("X-Auth-Token", token)
	}
	response, err := http.DefaultClient.Do(request)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		logrus.Errorf("http get Error %s", err)
		return nil, err, http.StatusNotAcceptable
	}
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		logrus.Errorf("Read error %s", err)
		return nil, err, http.StatusNoContent
	}
	return body, err, response.StatusCode
}

func getHTTPBodyDataByRfAPI(deviceIPAddress string, RfAPI string, token string) (bodyData map[string]interface{}, err error, statusCode int) {
	body, err, statusCode := getHTTPBodyByRfAPI(deviceIPAddress, RfAPI, token)
	if err != nil {
		logrus.Errorf("Failed to get the HTTP body %s", err)
		return nil, err, statusCode
	}
	bodyData = map[string]interface{}{}
	err = json.Unmarshal([]byte(body), &bodyData)
	if err != nil {
		logrus.Errorf("ErrorUnmarshal %s", err)
		return bodyData, err, http.StatusNoContent
	}
	return bodyData, err, statusCode
}

func postHTTPDataByRfAPI(deviceIPAddress string, RfAPI string, token string, data map[string]interface{}) (response *http.Response, body map[string]interface{}, err error, statusCode int) {
	if data == nil {
		logrus.Errorf("http body data error %s", err)
		return nil, nil, err, http.StatusNoContent
	}
	httpData, _ := json.Marshal(data)
	request, _ := http.NewRequest("POST", RfDefaultProtocol+deviceIPAddress+RfAPI, bytes.NewBuffer(httpData))
	request.Close = true
	if token != "" {
		request.Header.Add("X-Auth-Token", token)
	}
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		logrus.Errorf("client post error %s", err)
		return nil, nil, err, http.StatusNotAcceptable
	}
	if response != nil {
		defer response.Body.Close()
	}
	result := make(map[string]interface{})
	dec := json.NewDecoder(response.Body)
	if err = dec.Decode(&result); err != nil && err != io.EOF {
		logrus.Errorf("ERROR while post http data :%s ", err.Error())
		return response, nil, err, response.StatusCode
	}
	logrus.Infof("Result Decode %s", result)
	fmt.Println(result["data"])
	logrus.Errorf("HTTP response status:%s ", response.Status)
	return response, result, err, response.StatusCode
}

func patchHTTPDataByRfAPI(deviceIPAddress string, RfAPI string, token string, data map[string]interface{}) (response *http.Response, body map[string]interface{}, err error, statusCode int) {
	if data == nil {
		logrus.Errorf("http body data error %s", err)
		return nil, nil, err, http.StatusNoContent
	}
	httpData, _ := json.Marshal(data)
	request, _ := http.NewRequest("PATCH", RfDefaultProtocol+deviceIPAddress+RfAPI, bytes.NewBuffer(httpData))
	request.Close = true
	if token != "" {
		request.Header.Add("X-Auth-Token", token)
	}
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		logrus.Errorf("client patch error %s", err)
		return response, nil, err, http.StatusNotAcceptable
	}
	if response != nil {
		defer response.Body.Close()
	}
	result := make(map[string]interface{})
	dec := json.NewDecoder(response.Body)
	if err = dec.Decode(&result); err != nil && err != io.EOF {
		logrus.Errorf("ERROR while patch http data :%s ", err.Error())
		return response, nil, err, response.StatusCode
	}
	logrus.Infof("Result Decode %s", result)
	fmt.Println(result["data"])
	logrus.Errorf("HTTP response status:%s ", response.Status)
	return response, result, err, response.StatusCode
}

func deleteHTTPDataByRfAPI(deviceIPAddress string, RfAPI string, token string, data string) (response *http.Response, err error, statusCode int) {
	if len(RfAPI) != 0 {
		lastByte := RfAPI[len(RfAPI)-1:]
		if lastByte != "/" {
			RfAPI = RfAPI + "/"
		}
	}
	uri := RfDefaultProtocol + deviceIPAddress + RfAPI + data
	request, _ := http.NewRequest("DELETE", uri, nil)
	request.Close = true
	if token != "" {
		request.Header.Add("X-Auth-Token", token)
	}
	response, err = http.DefaultClient.Do(request)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		logrus.Errorf("Error Default Client %s", err)
	}
	return response, err, response.StatusCode
}

func (s *Server) getDeviceData(deviceIPAddress string, RfAPI string, token string, levelPos uint, keyword string) (retData []string) {
	deviceData, err, statusCode := getHTTPBodyDataByRfAPI(deviceIPAddress, RfAPI, token)
	if err != nil {
		logrus.Errorf("Failed to get device data %s status code %d", err, statusCode)
		return nil
	}
	archive := make(map[string]bool)
	archive[RfAPI] = true
	retData = parseMap(deviceData, 0, levelPos, archive, keyword)
	return retData
}

func (s *Server) getRedfishDeviceData(deviceData map[string]interface{}, RfAPI string, levelPos uint, keyword string) (retData []string) {
	archive := make(map[string]bool)
	archive[RfAPI] = true
	retData = parseMap(deviceData, 0, levelPos, archive, keyword)
	return retData
}

func getDeviceDataByMethod(deviceIPAddress string, RfAPI string, token string, httpMethod string, httpPostData map[string]interface{}, httpDeleteData string, httpPatchData map[string]interface{}) (statusCode int, retData map[string]interface{}, err error) {
	var httpData map[string]interface{}
	switch httpMethod {
	case "GET":
		httpData, _, statusCode = getHTTPBodyDataByRfAPI(deviceIPAddress, RfAPI, token)
		if statusCode != http.StatusOK {
			logrus.Errorf("Failed to get device data, status code %d", statusCode)
			return statusCode, httpData, errors.New("Failed to get device data")
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
