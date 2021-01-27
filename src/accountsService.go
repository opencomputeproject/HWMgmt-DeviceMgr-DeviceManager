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
	"strconv"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

//RfAccountsService :
const RfAccountsService = "/redfish/v1/AccountService/"

//RfAccountsServiceAccounts  :
const RfAccountsServiceAccounts = "/redfish/v1/AccountService/Accounts/"

//RfSessionService :
const RfSessionService = "/redfish/v1/SessionService/"

//RfSessionServiceSessions :
const RfSessionServiceSessions = "/redfish/v1/SessionService/Sessions/"

//RfSessionTimeOut :
const RfSessionTimeOut = 300

//UserPrivileges :
var UserPrivileges = []string{"Administrator", "Operator", "ReadOnlyUser"}

//UserNameMaxLength :
const UserNameMaxLength = 256

//PasswordMaxLength :
const PasswordMaxLength = 256

func (s *Server) getTokenByUser(deviceIPAddress string, userName string) string {
	if len(s.devicemap) != 0 {
		return s.devicemap[deviceIPAddress].UserLoginInfo[userName]
	}
	return ""
}

func (s *Server) getUserByToken(deviceIPAddress string, token string) string {
	if len(s.devicemap) != 0 {
		for userName, UserToken := range s.devicemap[deviceIPAddress].UserLoginInfo {
			if token == UserToken {
				return userName
			}
		}
	}
	return ""
}

func (s *Server) getUserStatus(deviceIPAddress string, token string, targetUser string) (status bool) {
	var found bool = false
	count := strings.Join(s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, token, 1, "Members@odata.count"), " ")
	if len(count) != 0 {
		userAPI := RfAccountsServiceAccounts + targetUser
		userList := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, token, 2, "@odata.id")
		if userList != nil {
			for _, user := range userList {
				if user == userAPI {
					found = true
					break
				}
			}
		}
	}
	return found
}

func (s *Server) getUserPrivilege(deviceIPAddress string, token string, targetUser string) string {
	var roleId string
	count := strings.Join(s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, token, 1, "Members@odata.count"), " ")
	if len(count) != 0 {
		userAPI := RfAccountsServiceAccounts + targetUser
		userList := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, token, 2, "@odata.id")
		if userList != nil {
			for _, user := range userList {
				if user == userAPI {
					roleId = strings.Join(s.getDeviceData(deviceIPAddress, userAPI, token, 1, "RoleId"), " ")
					break
				}
			}
		}
	}
	return roleId
}

func (s *Server) getLoginStatus(deviceIPAddress string, token string, targetUser string) bool {
	if len(targetUser) != 0 {
		sessions := s.getDeviceData(deviceIPAddress, RfSessionServiceSessions, token, 2, "@odata.id")
		if sessions != nil {
			for _, session := range sessions {
				if user := strings.Join(s.getDeviceData(deviceIPAddress, session, token, 1, "UserName"), " "); user == targetUser {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) validateDeviceAccountData(ip string, username string, password string) (errString string) {
	errString = ""
	if len(username) > UserNameMaxLength {
		errString = errString + "Device " + ip + ": " + "The device user name length has to below " + strconv.Itoa(UserNameMaxLength) + "characters\n"
	}
	if len(password) > PasswordMaxLength {
		errString = errString + "Device " + ip + ": " + "The device user password length has to below " + strconv.Itoa(PasswordMaxLength) + "characters\n"
	}
	return errString
}

func (s *Server) createDeviceAccount(deviceIPAddress string, token string, newUserName string, newPassword string, role string) (statusNum int, err error) {
	var statusCode int
	if s.getUserStatus(deviceIPAddress, token, newUserName) == true {
		logrus.Errorf("The user account %s is already in device %s", token, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + newUserName + " is already in device")
	}
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] {
		logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege is not administrator")
	}
	userInfo := map[string]interface{}{}
	userInfo["Name"] = "Account Service"
	if newUserName != "" {
		userInfo["UserName"] = newUserName
	} else {
		return http.StatusBadRequest, errors.New("The user username " + newUserName + " is invalid")
	}
	if newPassword != "" {
		userInfo["Password"] = newPassword
	} else {
		return http.StatusBadRequest, errors.New("The user password is invalid")
	}
	found := false
	for _, userPrivilege := range UserPrivileges {
		if role == userPrivilege {
			userInfo["RoleId"] = role
			found = true
		}
	}
	if found != true {
		return http.StatusBadRequest, errors.New("The user " + newUserName + " privilege is invalid")
	}
	userInfo["Enabled"] = true
	userInfo["Locked"] = false
	_, _, _, statusCode = postHTTPDataByRfAPI(deviceIPAddress, RfAccountsServiceAccounts, token, userInfo)
	if statusCode != http.StatusCreated {
		logrus.Errorf("Failed to create device account %s, status code %d", newUserName, statusCode)
		return statusCode, errors.New("Failed to create device account " + newUserName)
	}
	return statusCode, nil
}

func (s *Server) removeDeviceAccount(deviceIPAddress string, token string, removeUser string) (statusNum int, err error) {
	var statusCode int
	if s.getUserStatus(deviceIPAddress, token, removeUser) == false {
		logrus.Errorf("The user account %s is not available in device %s", token, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account " + removeUser + " is not available in device")
	}
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] {
		logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege is not administrator")
	} else {
		if userName == removeUser {
			logrus.Errorf("The user %s could not remove itself, device %s", userName, deviceIPAddress)
			return http.StatusBadRequest, errors.New("The user " + userName + " could not remove itself")
		}
	}
	sessions := s.getDeviceData(deviceIPAddress, RfSessionServiceSessions, token, 2, "@odata.id")
	if sessions != nil {
		for _, session := range sessions {
			if user := strings.Join(s.getDeviceData(deviceIPAddress, session, token, 1, "UserName"), " "); user == removeUser {
				id := strings.Join(s.getDeviceData(deviceIPAddress, session, token, 1, "Id"), " ")
				_, _, statusCode = deleteHTTPDataByRfAPI(deviceIPAddress, RfSessionServiceSessions, token, id)
				if statusCode != http.StatusOK {
					logrus.Errorf("Failed to delete login session id %s, status code %d", id, statusCode)
					return statusCode, errors.New("Failed to delete login session id " + id)
				}
			}
		}
		userLoginInfo := s.devicemap[deviceIPAddress].UserLoginInfo
		if len(userLoginInfo[removeUser]) != 0 {
			if _, found := userLoginInfo[removeUser]; found {
				delete(s.devicemap[deviceIPAddress].UserLoginInfo, removeUser)
				s.updateDataFile(deviceIPAddress)
			}
		}
	}
	_, _, statusCode = deleteHTTPDataByRfAPI(deviceIPAddress, RfAccountsServiceAccounts, token, removeUser)
	if statusCode != http.StatusOK {
		logrus.Errorf("Failed to delete device account %s, status code %d", removeUser, statusCode)
		return http.StatusNotFound, errors.New("Failed to delete device account " + removeUser)
	}
	return statusCode, nil
}

func (s *Server) setSessionService(deviceIPAddress string, token string, status bool, sessionTimeout uint64) (statusNum int, err error) {
	var statusCode int
	if len(token) != 0 {
		userName := s.getUserByToken(deviceIPAddress, token)
		if s.getUserStatus(deviceIPAddress, token, userName) == false {
			logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
			return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this device")
		}
		if s.getLoginStatus(deviceIPAddress, token, userName) == false {
			logrus.Errorf("The user account %s does not login in this device %s", userName, deviceIPAddress)
			return http.StatusBadRequest, errors.New("The user account " + userName + " is not available in device")
		}
		userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
		if userPrivilege != UserPrivileges[0] {
			logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
			return http.StatusBadRequest, errors.New("The user " + userName + " privilege is not administrator")
		}
	}
	if sessionTimeout < RfSessionTimeOut {
		logrus.Errorf("The seesion timeout has to over %d", RfSessionTimeOut)
		return http.StatusBadRequest, errors.New("The seesion timeout has to over " + strconv.Itoa(RfSessionTimeOut))
	}
	ServiceInfo := map[string]interface{}{}
	ServiceInfo["ServiceEnabled"] = status
	ServiceInfo["SessionTimeout"] = sessionTimeout
	_, _, _, statusCode = postHTTPDataByRfAPI(deviceIPAddress, RfSessionService, token, ServiceInfo)
	if statusCode != http.StatusOK {
		switch statusCode {
		case http.StatusUnauthorized:
			logrus.Errorf("The session service was enabled on the device %s. Please login device first and assige the token.", deviceIPAddress)
			return statusCode, errors.New("The session service was enabled on device " + deviceIPAddress +
				". Please login device first and assige the token.")
		default:
			logrus.Errorf("The session service was enabled on device %s, status code %d", deviceIPAddress, statusCode)
			return statusCode, errors.New("The session service was enabled on device " + deviceIPAddress +
				". The Status Code is " + strconv.Itoa(statusCode))
		}
	}
	return statusCode, nil
}

func (s *Server) loginDevice(deviceIPAddress string, token string, loginUserName string, loginPassword string) (RetToken string, statusNum int, err error) {
	var statusCode int
	serviceEnabled := strings.Join(s.getDeviceData(deviceIPAddress, RfSessionService, token, 1, "ServiceEnabled"), " ")
	if len(serviceEnabled) != 0 && serviceEnabled == "false" {
		logrus.Errorf("The session service does not enable yet, device %s", deviceIPAddress)
		return "", http.StatusBadRequest, errors.New("The session service does not enable yet, device " + deviceIPAddress)
	}
	if len(token) != 0 {
		userName := s.getUserByToken(deviceIPAddress, token)
		if s.getUserStatus(deviceIPAddress, token, userName) == false {
			logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
			return "", http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this device")
		}
	}
	userLoginInfo := map[string]interface{}{}
	userLoginInfo["UserName"] = loginUserName
	userLoginInfo["Password"] = loginPassword
	response, _, _, statusCode := postHTTPDataByRfAPI(deviceIPAddress, RfSessionServiceSessions, token, userLoginInfo)
	if statusCode != http.StatusCreated {
		logrus.Errorf("Failed to login device, status code %d", statusCode)
		return "", statusCode, errors.New("The user " + loginUserName + " failed to login this device " + deviceIPAddress)
	}
	if response != nil {
		RetToken = strings.Join(response.Header["X-Auth-Token"], " ")
		if len(RetToken) != 0 {
			s.devicemap[deviceIPAddress].UserLoginInfo[loginUserName] = RetToken
			s.updateDataFile(deviceIPAddress)
		}
	}
	return RetToken, statusCode, nil
}

func (s *Server) logoutDevice(deviceIPAddress string, token string, logoutUserName string) (statusNum int, err error) {
	var statusCode int
	if s.getLoginStatus(deviceIPAddress, token, logoutUserName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", logoutUserName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + logoutUserName + " does not login to this device")
	}
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, logoutUserName) == false {
		logrus.Errorf("The user account %s is not available in device %s", logoutUserName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + logoutUserName + " is not available in device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " is not available in device")
	}
	logoutUserPrivilege := s.getUserPrivilege(deviceIPAddress, token, logoutUserName)
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] {
		if (userPrivilege == UserPrivileges[1] && logoutUserPrivilege == UserPrivileges[0]) ||
			(userPrivilege == UserPrivileges[2] && logoutUserPrivilege != UserPrivileges[2]) {
			logrus.Errorf("The user %s privilege could not logout the other higher user from this device %s", userName, deviceIPAddress)
			return http.StatusBadRequest, errors.New("The user " + userName + " privilege could not logout the other higher user")
		}
	}
	sessions := s.getDeviceData(deviceIPAddress, RfSessionServiceSessions, token, 2, "@odata.id")
	if sessions != nil {
		for _, session := range sessions {
			if user := strings.Join(s.getDeviceData(deviceIPAddress, session, token, 1, "UserName"), " "); user == logoutUserName {
				id := strings.Join(s.getDeviceData(deviceIPAddress, session, token, 1, "Id"), " ")
				_, _, statusCode := deleteHTTPDataByRfAPI(deviceIPAddress, RfSessionServiceSessions, token, id)
				if statusCode != http.StatusOK {
					logrus.Errorf("Failed to delete login session id %s, status code %d", id, statusCode)
					return statusCode, errors.New("Failed to delete login session id " + id)
				}
			}
		}
	}
	userLoginInfo := s.devicemap[deviceIPAddress].UserLoginInfo
	if len(userLoginInfo[logoutUserName]) != 0 {
		if _, found := userLoginInfo[logoutUserName]; found {
			delete(s.devicemap[deviceIPAddress].UserLoginInfo, logoutUserName)
			s.updateDataFile(deviceIPAddress)
		}
	}
	return statusCode, nil
}

func (s *Server) changeDeviceUserPassword(deviceIPAddress string, token string, chgUsername string, chgPassword string) (statusNum int, err error) {
	if s.getUserStatus(deviceIPAddress, token, chgUsername) == false {
		logrus.Errorf("The user account %s is not available in device %s", chgUsername, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + chgUsername + " is not available in device")
	}
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " is not available in device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] {
		logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user " + userName + " privilege is not administrator")
	}
	pw := map[string]interface{}{}
	pw["Password"] = chgPassword
	_, _, _, statusCode := patchHTTPDataByRfAPI(deviceIPAddress, RfAccountsServiceAccounts+chgUsername, token, pw)
	if statusCode != http.StatusOK {
		logrus.Errorf("Failed to change device user (%s) password, status code %d", chgUsername, statusCode)
	}
	return statusCode, nil
}

func (s *Server) listDeviceAccount(deviceIPAddress string, token string) (deviceAccounts map[string]string, statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " does not login to this device")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusNotFound, errors.New("The user account " + userName + " is not available in device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] {
		logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user " + userName + " privilege is not administrator")
	}
	deviceAccounts = make(map[string]string)
	userLists := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, token, 2, "@odata.id")
	for _, userAPI := range userLists {
		user := strings.Join(s.getDeviceData(deviceIPAddress, userAPI, token, 1, "UserName"), " ")
		token := s.devicemap[deviceIPAddress].UserLoginInfo[user]
		deviceAccounts[user] = token
	}
	return deviceAccounts, http.StatusOK, nil
}
