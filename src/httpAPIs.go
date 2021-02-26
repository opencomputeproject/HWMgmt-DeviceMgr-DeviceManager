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
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	logrus "github.com/sirupsen/logrus"
)

//RfDefaultProtocol  :
const RfDefaultProtocol = "https://"

func getHTTPBodyByRfAPI(deviceIPAddress string, RfAPI string, token string) (body []byte, statusCode int, err error) {
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
		return nil, http.StatusNotAcceptable, err
	}
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		logrus.Errorf("Read error %s", err)
		return nil, http.StatusNoContent, err
	}
	return body, response.StatusCode, err
}

func getHTTPBodyDataByRfAPI(deviceIPAddress string, RfAPI string, token string) (bodyData map[string]interface{}, statusCode int, err error) {
	body, statusCode, err := getHTTPBodyByRfAPI(deviceIPAddress, RfAPI, token)
	if err != nil {
		logrus.Errorf("Failed to get the HTTP body %s", err)
		return nil, statusCode, err
	}
	bodyData = map[string]interface{}{}
	err = json.Unmarshal([]byte(body), &bodyData)
	if err != nil {
		logrus.Errorf("ErrorUnmarshal %s", err)
		return bodyData, http.StatusNoContent, err
	}
	return bodyData, statusCode, err
}

func postHTTPDataByRfAPI(deviceIPAddress string, RfAPI string, token string, data map[string]interface{}) (response *http.Response, body map[string]interface{}, statusCode int, err error) {
	if data == nil {
		logrus.Errorf("http body data error %s", err)
		return nil, nil, http.StatusNoContent, err
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
		return nil, nil, http.StatusNotAcceptable, err
	}
	if response != nil {
		defer response.Body.Close()
	}
	result := make(map[string]interface{})
	dec := json.NewDecoder(response.Body)
	if err = dec.Decode(&result); err != nil && err != io.EOF {
		logrus.Errorf("ERROR while post http data :%s ", err.Error())
		return response, nil, response.StatusCode, err
	}
	logrus.Infof("Result Decode %s", result)
	fmt.Println(result["data"])
	logrus.Errorf("HTTP response status:%s ", response.Status)
	return response, result, response.StatusCode, err
}

func patchHTTPDataByRfAPI(deviceIPAddress string, RfAPI string, token string, data map[string]interface{}) (response *http.Response, body map[string]interface{}, statusCode int, err error) {
	if data == nil {
		logrus.Errorf("http body data error %s", err)
		return nil, nil, http.StatusNoContent, err
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
		return response, nil, http.StatusNotAcceptable, err
	}
	if response != nil {
		defer response.Body.Close()
	}
	result := make(map[string]interface{})
	dec := json.NewDecoder(response.Body)
	if err = dec.Decode(&result); err != nil && err != io.EOF {
		logrus.Errorf("ERROR while patch http data :%s ", err.Error())
		return response, nil, response.StatusCode, err
	}
	logrus.Infof("Result Decode %s", result)
	fmt.Println(result["data"])
	logrus.Errorf("HTTP response status:%s ", response.Status)
	return response, result, response.StatusCode, err
}

func deleteHTTPDataByRfAPI(deviceIPAddress string, RfAPI string, token string, data string) (response *http.Response, statusCode int, err error) {
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
	return response, response.StatusCode, err
}

func (s *Server) getDeviceData(deviceIPAddress string, RfAPI string, token string, levelPos uint, keyword string) (retData []string) {
	deviceData, statusCode, err := getHTTPBodyDataByRfAPI(deviceIPAddress, RfAPI, token)
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
		httpData, statusCode, _ = getHTTPBodyDataByRfAPI(deviceIPAddress, RfAPI, token)
		if statusCode != http.StatusOK {
			logrus.Errorf("Failed to get device data, status code %d", statusCode)
			return statusCode, httpData, errors.New("Failed to get device data")
		}
	case "POST":
		_, httpData, statusCode, _ = postHTTPDataByRfAPI(deviceIPAddress, RfAPI, token, httpPostData)
		if statusCode != http.StatusOK && statusCode != http.StatusCreated {
			logrus.Errorf("Failed to post data to device, status code %d", statusCode)
			return statusCode, httpData, errors.New("Failed to post data to device")
		}
	case "DELETE":
		_, statusCode, _ = deleteHTTPDataByRfAPI(deviceIPAddress, RfAPI, token, httpDeleteData)
		if statusCode != http.StatusOK {
			logrus.Errorf("Failed to delete device data, status code %d, delete data %s", statusCode, httpDeleteData)
			return statusCode, httpData, errors.New("Failed to delete device data")
		}
	case "PATCH":
		_, httpData, statusCode, _ = patchHTTPDataByRfAPI(deviceIPAddress, RfAPI, token, httpPatchData)
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
