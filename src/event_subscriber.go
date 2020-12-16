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
	"regexp"
	"strings"

	logrus "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//RfEventService :
const RfEventService = "/redfish/v1/EventService/"

//RfSubscription :
const RfSubscription = RfEventService + "Subscriptions/"

func (s *Server) checkSubscription(deviceIPAddress string, token string) (currentEvent []string, statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user account " + userName + " is not available in deivce")
	}
	eventTypes := s.getDeviceData(deviceIPAddress, RfEventService, token, 1, "EventTypesForSubscription")
	subscriptions := s.getDeviceData(deviceIPAddress, RfSubscription, token, 2, "@odata.id")
	if subscriptions != nil {
		for _, subscription := range subscriptions {
			for _, event := range eventTypes {
				if eventType := s.getDeviceData(deviceIPAddress, subscription, token, 1, "EventTypes"); eventType[0] == event {
					id := strings.Join(s.getDeviceData(deviceIPAddress, subscription, token, 1, "Id"), " ")
					s.devicemap[deviceIPAddress].Subscriptions[event] = id
					currentEvent = append(currentEvent, event)
				}
			}
		}
		s.updateDataFile(deviceIPAddress)
	}
	return currentEvent, http.StatusOK, nil
}

func (s *Server) addSubscription(deviceIPAddress string, token string, events []string, eventServerAddr string, eventServerPort string) (statusNum int, err error) {
	var statusCode int
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " is not available in deivce")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	privilege := s.getDefineUserPrivilege(deviceIPAddress)
	if userPrivilege == privilege[2] {
		logrus.Errorf("The user %s privilege (%s) could not register event to this device %s", userName, privilege[2], deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege (" + privilege[2] + ") could not register event")
	}
	if len(eventServerAddr) == 0 {
		logrus.Errorf("The notification server address is empty")
		return http.StatusBadRequest, errors.New("The notification server address is empty")
	}
	if len(eventServerPort) == 0 {
		logrus.Errorf("The notification server port is empty")
		return http.StatusBadRequest, errors.New("The notification server port is empty")
	}
	destIP := eventServerAddr + ":" + eventServerPort
	subscrptInfo := map[string]interface{}{"Context": "EventServer-" + destIP, "Protocol": "Redfish"}
	subscrptInfo["Destination"] = destIP
	eventTypes := s.getDeviceData(deviceIPAddress, RfEventService, token, 1, "EventTypesForSubscription")
	currentEvent, statusCode, _ := s.checkSubscription(deviceIPAddress, token)
	if statusCode != http.StatusOK {
		return http.StatusNotFound, errors.New("Failed to get the current event list")
	}
	if len(events) == 0 {
		logrus.Errorf("No subscription is ready to register")
		return http.StatusBadRequest, errors.New("No subscription is ready to register")
	}
	var found bool
	for _, event := range events {
		found = false
		for _, eventType := range eventTypes {
			if event == eventType {
				found = true
				break
			}
		}
		if found == false {
			logrus.Errorf("The subscription ddoes not support (%s) ", event)
			return http.StatusBadRequest, errors.New("The subscription does not support (" + event + ")")
		}
		found = false
		for _, registeredEvent := range currentEvent {
			if event == registeredEvent {
				found = true
				break
			}
		}
		if found == true {
			logrus.Errorf("The subscription has registered (%s) ", event)
			return http.StatusBadRequest, errors.New("The subscription has registered (" + event + ")")
		}
		subscrptInfo["Name"] = event + " event subscription"
		subscrptInfo["EventTypes"] = []string{event}
		resp, _, _, statusCode := postHTTPDataByRfAPI(deviceIPAddress, RfSubscription, token, subscrptInfo)
		if statusCode != http.StatusCreated {
			logrus.Errorf("Failed to add subscription %s, status code %d", subscrptInfo, statusCode)
			return statusCode, errors.New("Failed to add subscription to device " + deviceIPAddress)
		}
		loc := resp.Header["Location"]
		re := regexp.MustCompile(`/(\w+)$`)
		match := re.FindStringSubmatch(loc[0])
		s.devicemap[deviceIPAddress].Subscriptions[event] = match[1]
	}
	s.updateDataFile(deviceIPAddress)
	logrus.Info("Subscription events was successfully added")
	return statusCode, nil
}

func (s *Server) removeSubscription(deviceIPAddress string, token string, events []string) (statusNum int, err error) {
	var statusCode int
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " is not available in deivce")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	privilege := s.getDefineUserPrivilege(deviceIPAddress)
	if userPrivilege == privilege[2] {
		logrus.Errorf("The user %s privilege (%s) could not unregister event to this device %s", userName, privilege[2], deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege (" + privilege[2] + ") could not unregister event")
	}
	eventTypes := s.getDeviceData(deviceIPAddress, RfEventService, token, 1, "EventTypesForSubscription")
	currentEvent, statusCode, _ := s.checkSubscription(deviceIPAddress, token)
	if statusCode != http.StatusOK {
		return http.StatusNotFound, errors.New("Failed to get the current event list")
	}
	if len(events) == 0 {
		logrus.Errorf("The current subscription is empty")
		return http.StatusBadRequest, errors.New("The current subscription is empty")
	}
	var found bool
	for _, event := range events {
		found = false
		for _, eventType := range eventTypes {
			if event == eventType {
				found = true
				break
			}
		}
		if found == false {
			logrus.Errorf("The subscription ddoes not support (%s) ", event)
			return http.StatusBadRequest, errors.New("The subscription does not support (" + event + ")")
		}
		found = false
		for _, registeredEvent := range currentEvent {
			if event == registeredEvent {
				found = true
				break
			}
		}
		if found == false {
			logrus.Errorf("The subscription has not registered (%s) ", event)
			return http.StatusBadRequest, errors.New("The subscription has not registered (" + event + ")")
		}
		subscriptions := s.getDeviceData(deviceIPAddress, RfSubscription, token, 2, "@odata.id")
		for _, subscription := range subscriptions {
			if eventType := s.getDeviceData(deviceIPAddress, subscription, token, 1, "EventTypes"); eventType[0] == event {
				id := strings.Join(s.getDeviceData(deviceIPAddress, subscription, token, 1, "Id"), " ")
				if len(id) != 0 {
					_, _, statusCode = deleteHTTPDataByRfAPI(deviceIPAddress, RfSubscription, token, id)
					if statusCode != http.StatusNoContent {
						logrus.Errorf("Failed to delete substription id %s, status code %d", event, statusCode)
						return statusCode, errors.New("Failed to delete subscription id " + event + " to device " + deviceIPAddress)
					}
					delete(s.devicemap[deviceIPAddress].Subscriptions, event)
				}
			}
		}
	}
	s.updateDataFile(deviceIPAddress)
	logrus.Info("Subscription events was successfully removed")
	return statusCode, nil
}

func (s *Server) getEventList(deviceIPAddress string, token string) (events []string, statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user account " + userName + " is not available in deivce")
	}
	eventTypes := s.getDeviceData(deviceIPAddress, RfEventService, token, 1, "EventTypesForSubscription")
	if eventTypes == nil {
		return nil, http.StatusNotFound, status.Errorf(codes.NotFound, http.StatusText(http.StatusNotFound))
	}
	s.devicemap[deviceIPAddress].Eventtypes = eventTypes
	events = s.devicemap[deviceIPAddress].Eventtypes
	s.updateDataFile(deviceIPAddress)
	return events, http.StatusOK, nil
}
