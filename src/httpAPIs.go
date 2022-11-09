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
	"strconv"

	logrus "github.com/sirupsen/logrus"
)

const (
	//UserAgent ...
	UserAgent = "DeviceManager"
	//Accept ...
	Accept = "*/*"
)

//ContentType ...
var DefaultContentType string = "application/json"
var ContentType = make(map[string]string)

//RfDefaultProtocol ...
var RfDefaultHttpsProtocol = "https://"
var RfDefaultHttpProtocol = "http://"
var RfProtocol = make(map[string]string)

func addAuthHeader(request *http.Request, userAuthData userAuth) {
	if (userAuthData != userAuth{}) {
		if userAuthData.PassAuth == false {
		if userAuthData.AuthType == authTypeEnum.BASIC {
			request.SetBasicAuth(userAuthData.UserName, userAuthData.Password)
		} else {
			if userAuthData.Token != "" {
				request.Header.Add("X-Auth-Token", userAuthData.Token)
				}
			}
		}
	}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New(ErrHTTPRedirectTimeOut.String())
	}
	return nil
}

func httpRedirction(request *http.Request) (client *http.Client, location string, shouldRedirect bool, err error) {
	response, err := http.DefaultTransport.RoundTrip(request)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return nil, "", false, err
	}
	location = response.Header.Get("Location")
	shouldRedirect = false
	if location != "" && response.StatusCode == http.StatusPermanentRedirect {
		shouldRedirect = true
	}
	client = &http.Client{
		CheckRedirect: checkRedirect,
	}
	return client, location, shouldRedirect, err
}

func performHTTPRedirection(method string, client *http.Client, location string) (response *http.Response, err error) {
	location = addSlashToTail(location)
	response, err = client.Get(location)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return nil, errors.New(ErrHTTPRedirectGetFailed.String(method, err.Error()))
	}
	return response, err
}

func getHTTPBodyByRfAPI(deviceIPAddress, RfAPI string, userAuthData userAuth) (body []byte, statusCode int, err error) {
	var request *http.Request
	RfAPI = addSlashToTail(RfAPI)
	var url string
	if RfProtocol != nil && RfProtocol[deviceIPAddress] != "" {
		url = RfProtocol[deviceIPAddress] + deviceIPAddress + RfAPI
	} else {
		url = RfDefaultHttpsProtocol + deviceIPAddress + RfAPI
	}
	request, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	request.Close = true
	addAuthHeader(request, userAuthData)
	request.Header.Add("User-Agent", UserAgent)
	request.Header.Add("Accept", Accept)
	client, loc, shouldRedirect, err := httpRedirction(request)
	if err != nil {
		return nil, http.StatusMisdirectedRequest, err
	}
	var response *http.Response
	if shouldRedirect {
		response, err = performHTTPRedirection("GET", client, loc)
		if err != nil {
			logrus.Errorf(err.Error())
			return nil, http.StatusNotAcceptable, err
		}
	} else {
		response, err = http.DefaultClient.Do(request)
		if response != nil {
			defer response.Body.Close()
		}
		if err != nil {
			logrus.Errorf(ErrHTTPGetDataFailed.String(err.Error()))
			return nil, http.StatusNotAcceptable, err
		}
	}
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		logrus.Errorf(ErrHTTPReadBodyFailed.String(err.Error()))
		return nil, http.StatusNoContent, err
	}
	return body, response.StatusCode, err
}

func getHTTPBodyDataByRfAPI(deviceIPAddress, RfAPI string, userAuthData userAuth) (bodyData map[string]interface{}, statusCode int, err error) {
	body, statusCode, err := getHTTPBodyByRfAPI(deviceIPAddress, RfAPI, userAuthData)
	if err != nil || body == nil {
		logrus.Errorf(ErrHTTPGetBody.String(err.Error(), strconv.Itoa(statusCode)))
		return nil, statusCode, err
	}
	bodyData = nil
	if statusCode == http.StatusOK {
		if len(body) != 0 {
			bodyData = map[string]interface{}{}
			err = json.Unmarshal([]byte(body), &bodyData)
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
	return bodyData, statusCode, err
}

func postHTTPDataByRfAPI(deviceIPAddress, RfAPI string, userAuthData userAuth, data interface{}) (response *http.Response, body map[string]interface{}, statusCode int, err error) {
	var request *http.Request
	if data == nil {
		logrus.Errorf(ErrHTTPBodyEmpty.String())
		return nil, nil, http.StatusNoContent, err
	}
	httpData, _ := json.Marshal(data)
	if RfProtocol != nil && RfProtocol[deviceIPAddress] != "" {
		request, _ = http.NewRequest("POST", RfProtocol[deviceIPAddress]+deviceIPAddress+RfAPI, bytes.NewBuffer(httpData))
	} else {
		request, _ = http.NewRequest("POST", RfDefaultHttpsProtocol+deviceIPAddress+RfAPI, bytes.NewBuffer(httpData))
	}
	request.Close = true
	addAuthHeader(request, userAuthData)
	if ContentType != nil && ContentType[deviceIPAddress] != "" {
		request.Header.Add("Content-Type", ContentType[deviceIPAddress])
	}
	request.Header.Add("User-Agent", UserAgent)
	request.Header.Add("Accept", Accept)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		logrus.Errorf(ErrHTTPPostDataFailed.String(err.Error()))
		return nil, nil, http.StatusNotAcceptable, err
	}
	if response != nil {
		defer response.Body.Close()
	}
	result := make(map[string]interface{})
	dec := json.NewDecoder(response.Body)
	if decErr := dec.Decode(&result); decErr != nil && decErr != io.EOF {
		logrus.Errorf(ErrHTTPDecodeBodyFailed.String(decErr.Error()))
		return response, nil, response.StatusCode, decErr
	}
	logrus.Infof("Result Decode %s", result)
	fmt.Println(result["data"])
	logrus.Infof("HTTP response status: %s", response.Status)
	return response, result, response.StatusCode, err
}

func patchHTTPDataByRfAPI(deviceIPAddress, RfAPI string, userAuthData userAuth, data interface{}) (response *http.Response, body map[string]interface{}, statusCode int, err error) {
	var request *http.Request
	if data == nil {
		logrus.Errorf(ErrHTTPBodyEmpty.String())
		return nil, nil, http.StatusNoContent, err
	}
	httpData, _ := json.Marshal(data)
	if RfProtocol != nil && RfProtocol[deviceIPAddress] != "" {
		request, _ = http.NewRequest("PATCH", RfProtocol[deviceIPAddress]+deviceIPAddress+RfAPI, bytes.NewBuffer(httpData))
	} else {
		request, _ = http.NewRequest("PATCH", RfDefaultHttpsProtocol+deviceIPAddress+RfAPI, bytes.NewBuffer(httpData))
	}
	request.Close = true
	addAuthHeader(request, userAuthData)
	if ContentType != nil && ContentType[deviceIPAddress] != "" {
		request.Header.Add("Content-Type", ContentType[deviceIPAddress])
	}
	request.Header.Add("User-Agent", UserAgent)
	request.Header.Add("Accept", Accept)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		logrus.Errorf(ErrHTTPPatchDataFailed.String(err.Error()))
		return response, nil, http.StatusNotAcceptable, err
	}
	if response != nil {
		defer response.Body.Close()
	}
	result := make(map[string]interface{})
	dec := json.NewDecoder(response.Body)
	if decErr := dec.Decode(&result); decErr != nil && decErr != io.EOF {
		logrus.Errorf(ErrHTTPDecodeBodyFailed.String(decErr.Error()))
		return response, nil, response.StatusCode, decErr
	}
	logrus.Infof("Result Decode %s", result)
	fmt.Println(result["data"])
	logrus.Infof("HTTP response status: %s", response.Status)
	return response, result, response.StatusCode, err
}

func deleteHTTPDataByRfAPI(deviceIPAddress, RfAPI string, userAuthData userAuth, data string) (response *http.Response, statusCode int, err error) {
	var uri string
	if len(RfAPI) != 0 {
		RfAPI = addSlashToTail(RfAPI)
	}
	if RfProtocol != nil && RfProtocol[deviceIPAddress] != "" {
		uri = RfProtocol[deviceIPAddress] + deviceIPAddress + RfAPI + data
	} else {
		uri = RfDefaultHttpsProtocol + deviceIPAddress + RfAPI + data
	}
	request, _ := http.NewRequest("DELETE", uri, nil)
	request.Close = true
	addAuthHeader(request, userAuthData)
	request.Header.Add("User-Agent", UserAgent)
	request.Header.Add("Accept", Accept)
	response, err = http.DefaultClient.Do(request)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		logrus.Errorf(ErrHTTPDeleteDataFailed.String(err.Error()))
	}
	return response, response.StatusCode, err
}

func (s *Server) getDeviceData(deviceIPAddress, RfAPI, authStr string, levelPos uint, keyword string) (retData []string, statusCode int, err error) {
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return nil, http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	deviceData, statusCode, err := getHTTPBodyDataByRfAPI(deviceIPAddress, RfAPI, userAuthData)
	if statusCode != http.StatusOK || err != nil {
		logrus.Errorf(ErrGetDeviceData.String(strconv.Itoa(statusCode)))
		return nil, statusCode, err
	}
	archive := make(map[string]bool)
	retData, found := parseMap(deviceData, 0, levelPos, archive, keyword)
	if found == false {
		return retData, http.StatusNotFound, errors.New(ErrFailedToFindData.String())
	}
	return retData, statusCode, err
}

func (s *Server) getRedfishDeviceData(deviceData map[string]interface{}, levelPos uint, keyword string) (retData []string) {
	archive := make(map[string]bool)
	retData, _ = parseMap(deviceData, 0, levelPos, archive, keyword)
	return retData
}
