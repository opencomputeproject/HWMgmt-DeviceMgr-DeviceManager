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
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	logrus "github.com/sirupsen/logrus"
)

const (
	//RfAccountsService ...
	RfAccountsService = "/redfish/v1/AccountService/"
	//RfAccountsServiceAccounts ...
	RfAccountsServiceAccounts = "/redfish/v1/AccountService/Accounts/"
	//RfAccountsServiceRoles ...
	RfAccountsServiceRoles = "/redfish/v1/AccountService/Roles"
	//RfSessionService ...
	RfSessionService = "/redfish/v1/SessionService/"
	//RfSessionServiceSessions ...
	RfSessionServiceSessions = "/redfish/v1/SessionService/Sessions/"
	//RfSessionTimeOut ...
	RfSessionTimeOut = 300
)

const (
	//UserNameMaxLength ...
	UserNameMaxLength = 256
	//PasswordMaxLength ...
	PasswordMaxLength = 256
)

var (
	//UserPrivileges ...
	UserPrivileges = []string{"Administrator", "Operator", "ReadOnly"}
	//AdminstratorAssignedPrivileges ...
	AdminstratorAssignedPrivileges = []string{"Login", "ConfigureManager", "ConfigureUsers", "ConfigureSelf", "ConfigureComponents"}
	//OperatorAssignedPrivileges ...
	OperatorAssignedPrivileges = []string{"Login", "ConfigureSelf", "ConfigureComponents"}
	//ReadOnlyUserAssignedPrivileges ...
	ReadOnlyUserAssignedPrivileges = []string{"Login", "ConfigureSelf"}
)

func (s *Server) getAuthTypeEnum(authType bool) int {
	return func() int {
		if authType == false {
			return authTypeEnum.TOKEN
		} else {
			return authTypeEnum.BASIC
		}
	}()
}

func (s *Server) updateAuthData(deviceIPAddress, token, userName, password string, authType bool) userAuth {
	if s.devicemap[deviceIPAddress] != nil {
		s.devicemap[deviceIPAddress].UserAuthLock.Lock()
		defer s.devicemap[deviceIPAddress].UserAuthLock.Unlock()
		if len(deviceIPAddress) != 0 && s.devicemap[deviceIPAddress] != nil {
			aType := s.getAuthTypeEnum(authType)
			s.devicemap[deviceIPAddress].UserLoginInfo[userName] = userAuth{AuthType: aType,
				Token:    token,
				UserName: userName,
				Password: password}
			return s.devicemap[deviceIPAddress].UserLoginInfo[userName]
		}
	}
	return userAuth{}
}

func (s *Server) getUserAuthData(deviceIPAddress, authStr string) userAuth {
	if s.devicemap[deviceIPAddress] != nil {
		s.devicemap[deviceIPAddress].UserAuthLock.Lock()
		defer s.devicemap[deviceIPAddress].UserAuthLock.Unlock()
		if authStr != "" {
			userLoginInfo := s.devicemap[deviceIPAddress].UserLoginInfo
			for userName, userAuthData := range userLoginInfo {
				if userAuthData.Token == authStr || userName == authStr {
					return userAuthData
				}
			}
		} else if authStr == "" {
			if s.devicemap[deviceIPAddress].PassAuth == true {
				return userAuth{AuthType: authTypeEnum.NONE}
			}
		}
	} else if authStr == "" {
		return userAuth{AuthType: authTypeEnum.NONE}
	}
	return userAuth{}
}

func (s *Server) getAuthStrByUser(deviceIPAddress, user string) string {
	if s.devicemap[deviceIPAddress] != nil {
		s.devicemap[deviceIPAddress].UserAuthLock.Lock()
		defer s.devicemap[deviceIPAddress].UserAuthLock.Unlock()
		if user != "" && s.devicemap[deviceIPAddress] != nil {
			userLoginInfo := s.devicemap[deviceIPAddress].UserLoginInfo
			for userName, userAuthData := range userLoginInfo {
				if user == userName {
					switch userAuthData.AuthType {
					case authTypeEnum.TOKEN:
						return userAuthData.Token
					case authTypeEnum.BASIC:
						return userAuthData.UserName
					}
				}
			}
		}
	}
	return ""
}

func (s *Server) getUserByToken(deviceIPAddress string, token string) string {
	if s.devicemap[deviceIPAddress] != nil {
		s.devicemap[deviceIPAddress].UserAuthLock.Lock()
		defer s.devicemap[deviceIPAddress].UserAuthLock.Unlock()
		if len(s.devicemap) != 0 {
			for userName, userAuthData := range s.devicemap[deviceIPAddress].UserLoginInfo {
				if token == userAuthData.Token {
					return userName
				}
			}
		}
	}
	return ""
}

func (s *Server) getUserLoginID(deviceIPAddress, authStr, userName string) (id string, status bool, statusCode int, err error) {
	var found bool
	found = false
	sessions, statusCode, err := s.getDeviceData(deviceIPAddress, RfSessionServiceSessions, authStr, 2, "@odata.id")
	if sessions != nil {
		for _, session := range sessions {
			userData, statusCode, err := s.getDeviceData(deviceIPAddress, session, authStr, 1, "UserName")
			if user := strings.Join(userData, " "); user == userName && err == nil && statusCode == http.StatusOK {
				idData, statusCode, err := s.getDeviceData(deviceIPAddress, session, authStr, 1, "Id")
				if idData != nil && err == nil && statusCode == http.StatusOK {
					id = strings.Join(idData, " ")
					found = true
					break
				}
			}
		}
	}
	return id, found, statusCode, err
}

func (s *Server) getAccountDataByLabel(deviceIPAddress, authStr, userName, label string) (labelData string, status bool) {
	var found bool
	found = false
	accounts, _, _ := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, authStr, 2, "@odata.id")
	if accounts != nil {
		for _, account := range accounts {
			userData, _, _ := s.getDeviceData(deviceIPAddress, account, authStr, 1, "UserName")
			if userData != nil {
				if user := strings.Join(userData, " "); user == userName {
					data, _, _ := s.getDeviceData(deviceIPAddress, account, authStr, 1, label)
					labelData = strings.Join(data, " ")
					found = true
					break
				}
			}
		}
	}
	return labelData, found
}

func (s *Server) deleteDeviceSession(deviceIPAddress, authStr, userName string, userAuthData userAuth) (statusCode int, err error) {
	id, status, statusCode, err := s.getUserLoginID(deviceIPAddress, authStr, userName)
	if err == nil && status == true {
		_, statusCode, err = deleteHTTPDataByRfAPI(deviceIPAddress, RfSessionServiceSessions, userAuthData, id)
		if statusCode != http.StatusOK {
			logrus.Errorf(ErrDeleteLoginFailed.String(id, strconv.Itoa(statusCode)))
			return statusCode, errors.New(ErrDeleteLoginFailed.String(id, strconv.Itoa(statusCode)))
		}
	}
	return statusCode, err
}

func (s *Server) getUserStatus(deviceIPAddress, authStr, targetUser string) (status bool) {
	var found bool
	found = false
	odata, _, _ := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, authStr, 1, "Members@odata.count")
	count := strings.Join(odata, " ")
	if len(count) != 0 {
		userList, _, _ := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, authStr, 2, "@odata.id")
		if userList != nil {
			for _, user := range userList {
				userData, _, _ := s.getDeviceData(deviceIPAddress, user, authStr, 1, "UserName")
				if userData != nil {
					userName := strings.Join(userData, " ")
					if userName == targetUser {
						found = true
						break
					}
				}
			}
		}
	}
	return found
}

func (s *Server) getDefineUserPrivilege(deviceIPAddress, authStr string) map[int]string {
	index := 0
	userPrivilege := map[int]string{}
	odata, _, _ := s.getDeviceData(deviceIPAddress, RfAccountsServiceRoles, authStr, 1, "Members@odata.count")
	count := strings.Join(odata, " ")
	if len(count) != 0 {
		rulesList, _, _ := s.getDeviceData(deviceIPAddress, RfAccountsServiceRoles, authStr, 2, "@odata.id")
		if rulesList != nil {
			for _, role := range rulesList {
				privilege, _, _ := s.getDeviceData(deviceIPAddress, role, authStr, 1, "Id")
				if len(privilege[0]) != 0 {
					userPrivilege[index], index = privilege[0], index+1
				} else {
					privilegesData, _, _ := s.getDeviceData(deviceIPAddress, role, authStr, 1, "AssignedPrivileges")
					if reflect.DeepEqual(privilegesData, AdminstratorAssignedPrivileges) == true {
						userPrivilege[index], index = UserPrivileges[0], index+1
					} else if reflect.DeepEqual(privilegesData, OperatorAssignedPrivileges) == true {
						userPrivilege[index], index = UserPrivileges[1], index+1
					} else if reflect.DeepEqual(privilegesData, ReadOnlyUserAssignedPrivileges) == true {
						userPrivilege[index], index = UserPrivileges[2], index+1
					}
				}
			}
		}
	}
	return userPrivilege
}

func (s *Server) getUserPrivilege(deviceIPAddress, authStr, targetUser string) string {
	var roleID string
	odata, _, _ := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, authStr, 1, "Members@odata.count")
	count := strings.Join(odata, " ")
	if len(count) != 0 {
		userList, _, _ := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, authStr, 2, "@odata.id")
		if userList != nil {
			for _, user := range userList {
				userData, _, _ := s.getDeviceData(deviceIPAddress, user, authStr, 1, "UserName")
				if userData != nil {
					userName := strings.Join(userData, " ")
					if userName == targetUser {
						roleData, _, _ := s.getDeviceData(deviceIPAddress, user, authStr, 1, "RoleId")
						roleID = strings.Join(roleData, " ")
						break
					}
				}
			}
		}
	}
	return roleID
}

func (s *Server) getLoginStatus(deviceIPAddress, authStr, targetUser string) bool {
	if len(targetUser) != 0 {
		sessions, _, _ := s.getDeviceData(deviceIPAddress, RfSessionServiceSessions, authStr, 2, "@odata.id")
		if sessions != nil {
			for _, session := range sessions {
				userData, _, _ := s.getDeviceData(deviceIPAddress, session, authStr, 1, "UserName")
				if user := strings.Join(userData, " "); user == targetUser {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) validateDeviceAccountData(ip, username, password string) (errString string) {
	errString = ""
	if len(username) > UserNameMaxLength {
		errString = errString + ErrUsernameLength.String(ip, strconv.Itoa(UserNameMaxLength)) + "\n"
	}
	if len(password) > PasswordMaxLength {
		errString = errString + ErrUserPwdLength.String(ip, strconv.Itoa(PasswordMaxLength)) + "\n"
	}
	return errString
}

func (s *Server) createDeviceAccount(deviceIPAddress, authStr, newUserName, newPassword, role string) (statusNum int, err error) {
	var statusCode int
	userInfo := map[string]interface{}{}
	if newUserName != "" {
		userInfo["UserName"] = newUserName
	} else {
		return http.StatusBadRequest, errors.New(ErrUsername.String(newUserName))
	}
	if newPassword != "" {
		userInfo["Password"] = newPassword
	} else {
		return http.StatusBadRequest, errors.New(ErrPassword.String())
	}
	found := false
	for _, userPrivilege := range s.getDefineUserPrivilege(deviceIPAddress, authStr) {
		if role == userPrivilege {
			userInfo["RoleId"] = role
			found = true
		}
	}
	if found != true {
		return http.StatusBadRequest, errors.New(ErrUserPrivilegeInvalid.String(newUserName))
	}
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	userInfo["Enabled"] = true
	_, _, statusCode, _ = postHTTPDataByRfAPI(deviceIPAddress, RfAccountsServiceAccounts, userAuthData, userInfo)
	if statusCode != http.StatusCreated {
		logrus.Errorf(ErrCreateUserAccount.String(newUserName, strconv.Itoa(statusCode)))
		return statusCode, errors.New(ErrCreateUserAccount.String(newUserName, strconv.Itoa(statusCode)))
	}
	return statusCode, nil
}

func (s *Server) removeDeviceAccount(deviceIPAddress string, authStr string, removeUser string) (statusNum int, err error) {
	var statusCode int
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	id, status, _, _ := s.getUserLoginID(deviceIPAddress, authStr, removeUser)
	if status == true {
		_, statusCode, _ = deleteHTTPDataByRfAPI(deviceIPAddress, RfSessionServiceSessions, userAuthData, id)
		if statusCode != http.StatusOK {
			logrus.Errorf(ErrDeleteLoginFailed.String(id, strconv.Itoa(statusCode)))
			return statusCode, errors.New(ErrDeleteLoginFailed.String(id, strconv.Itoa(statusCode)))
		}
	}
	id, status = s.getAccountDataByLabel(deviceIPAddress, authStr, removeUser, "Id")
	if status == true {
		_, statusCode, _ = deleteHTTPDataByRfAPI(deviceIPAddress, RfAccountsServiceAccounts, userAuthData, id)
		if statusCode != http.StatusOK {
			logrus.Errorf(ErrDeleteUserAccount.String(removeUser, strconv.Itoa(statusCode)))
			return http.StatusNotFound, errors.New(ErrDeleteUserAccount.String(removeUser, strconv.Itoa(statusCode)))
		}
	}
	userLoginInfo := s.devicemap[deviceIPAddress].UserLoginInfo
	if _, found := userLoginInfo[removeUser]; found {
		delete(s.devicemap[deviceIPAddress].UserLoginInfo, removeUser)
		s.updateDataFile(deviceIPAddress)
	}
	return statusCode, nil
}

func (s *Server) setSessionService(deviceIPAddress, authStr string, status bool, sessionTimeout uint64) (statusNum int, err error) {
	var statusCode int
	//sessionTimeout is 0 means disable session timeout
	if sessionTimeout != 0 {
		//set sessionTimeout and over RfSessionTimeOut
		if sessionTimeout < RfSessionTimeOut {
			logrus.Errorf(ErrSessionTimeout.String(strconv.Itoa(RfSessionTimeOut)))
			return http.StatusBadRequest, errors.New(ErrSessionTimeout.String(strconv.Itoa(RfSessionTimeOut)))
		}
	}
	ServiceInfo := map[string]interface{}{}
	ServiceInfo["ServiceEnabled"] = status
	ServiceInfo["SessionTimeout"] = sessionTimeout
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if authStr != "" {
		if (userAuthData == userAuth{}) {
			logrus.Errorf(ErrUserAuthNotFound.String())
			return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
		}
	}
	_, _, statusCode, _ = patchHTTPDataByRfAPI(deviceIPAddress, RfSessionService, userAuthData, ServiceInfo)
	if statusCode != http.StatusOK {
		switch statusCode {
		case http.StatusMethodNotAllowed:
			logrus.Errorf(ErrSessionExists.String(deviceIPAddress))
			return statusCode, errors.New(ErrSessionExists.String(deviceIPAddress))
		default:
			logrus.Errorf(ErrSessionFailed.String(deviceIPAddress, strconv.Itoa(statusCode)))
			return statusCode, errors.New(ErrSessionFailed.String(deviceIPAddress, strconv.Itoa(statusCode)))
		}
	}
	return statusCode, nil
}

func (s *Server) loginDevice(deviceIPAddress, loginUserName, loginPassword string, authType bool) (RetToken string, statusNum int, err error) {
	var statusCode int
	defer func() {
		if err != nil {
			delete(s.devicemap[deviceIPAddress].UserLoginInfo, loginUserName)
		}
	}()
	userAuthData := s.updateAuthData(deviceIPAddress, "", loginUserName, loginPassword, authType)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return "", statusNum, errors.New(ErrUserAuthNotFound.String())
	}
	if userAuthData.AuthType == authTypeEnum.TOKEN {
		serviceData, statusNum, err := s.getDeviceData(deviceIPAddress, RfSessionService, loginUserName, 1, "ServiceEnabled")
		if statusNum == http.StatusOK {
			//check another http error then return
			if err != nil {
				return "", statusNum, err
			}
			serviceEnabled := strings.Join(serviceData, " ")
			if len(serviceEnabled) != 0 && serviceEnabled == "false" {
				logrus.Errorf(ErrSessionNotSet.String(deviceIPAddress))
				return "", http.StatusBadRequest, errors.New(ErrSessionNotSet.String(deviceIPAddress))
			}
		}
		userLoginInfo := map[string]interface{}{}
		userLoginInfo["UserName"] = loginUserName
		userLoginInfo["Password"] = loginPassword
		response, _, statusCode, err := postHTTPDataByRfAPI(deviceIPAddress, RfSessionServiceSessions, userAuthData, userLoginInfo)
		switch statusCode {
		//Now, check the session service has enabled or not
		case http.StatusCreated:
			if response != nil {
				if authType == false {
					RetToken = strings.Join(response.Header["X-Auth-Token"], " ")
					userAuthData.Token = RetToken
				}
				s.devicemap[deviceIPAddress].UserLoginInfo[loginUserName] = userAuthData
				return RetToken, statusCode, err
			} else {
				logrus.Errorf(ErrLoginFailed.String(strconv.Itoa(statusCode)))
				return "", statusCode, errors.New(ErrLoginFailed.String(strconv.Itoa(statusCode)))
			}
		default:
			switch statusCode {
			case http.StatusUnauthorized:
				logrus.Errorf(ErrUserAuthNotFound.String(strconv.Itoa(statusCode)))
				return "", statusCode, errors.New(ErrUserAuthNotFound.String(strconv.Itoa(statusCode)))
			default:
				logrus.Errorf(ErrLoginFailed.String(strconv.Itoa(statusCode)))
				return "", statusCode, errors.New(ErrLoginFailed.String(strconv.Itoa(statusCode)))
			}
		}
	} else if userAuthData.AuthType == authTypeEnum.BASIC {
		authStr := s.getAuthStrByUser(deviceIPAddress, loginUserName)
		if _, AccountStatus := s.getAccountDataByLabel(deviceIPAddress, authStr, loginUserName, "Id"); AccountStatus == true {
			if status, errors := s.deleteDeviceSession(deviceIPAddress, authStr, loginUserName, userAuthData); errors != nil {
				return "", status, errors
			}
			s.updateDataFile(deviceIPAddress)
			s.devicemap[deviceIPAddress].QueryUser = userAuthData
		} else {
			logrus.Errorf(ErrUserAuthNotFound.String(strconv.Itoa(statusCode)))
			return "", http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String(strconv.Itoa(statusCode)))
		}
		return loginUserName, statusCode, err
	}
	return "", statusCode, err
}

func (s *Server) logoutDevice(deviceIPAddress, authStr, logoutUserName string) (statusNum int, err error) {
	var statusCode int
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	logoutUserAuthData := s.getUserAuthData(deviceIPAddress, logoutUserName)
	if (logoutUserAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	if logoutUserAuthData.AuthType == authTypeEnum.TOKEN {
		if statusCode, err = s.deleteDeviceSession(deviceIPAddress, authStr, logoutUserName, userAuthData); err != nil {
			return statusCode, err
		}
		userLoginInfo := s.devicemap[deviceIPAddress].UserLoginInfo
		if _, found := userLoginInfo[logoutUserName]; found {
			delete(s.devicemap[deviceIPAddress].UserLoginInfo, logoutUserName)
			s.updateDataFile(deviceIPAddress)
		}
	} else {
		return http.StatusBadRequest, errors.New(ErrUserIsBasicAuth.String())
	}
	return statusCode, err
}

func (s *Server) changeDeviceUserPassword(deviceIPAddress, authStr, chgUsername, chgPassword string) (statusNum int, err error) {
	var statusCode int
	pw := map[string]interface{}{}
	pw["Password"] = chgPassword
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	id, status := s.getAccountDataByLabel(deviceIPAddress, authStr, chgUsername, "Id")
	if status == true {
		_, _, statusCode, _ = patchHTTPDataByRfAPI(deviceIPAddress, RfAccountsServiceAccounts+id, userAuthData, pw)
		if statusCode != http.StatusOK {
			logrus.Errorf(ErrChangePwdFailed.String(chgUsername, strconv.Itoa(statusCode)))
			return statusCode, errors.New(ErrChangePwdFailed.String(chgUsername, strconv.Itoa(statusCode)))
		} else {
			userAuthData.Password = chgPassword
			s.devicemap[deviceIPAddress].UserLoginInfo[chgUsername] = userAuthData
			s.updateDataFile(deviceIPAddress)
		}
	}
	return statusCode, nil
}

func (s *Server) listDeviceAccount(deviceIPAddress, authStr string) (deviceAccounts map[string]string, statusNum int, err error) {
	deviceAccounts = make(map[string]string)
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return nil, http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	userLists, _, _ := s.getDeviceData(deviceIPAddress, RfAccountsServiceAccounts, authStr, 2, "@odata.id")
	for _, userAPI := range userLists {
		userData, _, _ := s.getDeviceData(deviceIPAddress, userAPI, authStr, 1, "UserName")
		if userData != nil {
			user := strings.Join(userData, " ")
			if user != "" {
				if userAuthData = s.getUserAuthData(deviceIPAddress, user); (userAuthData == userAuth{}) {
					if userData, _, _ = s.getDeviceData(deviceIPAddress, userAPI, authStr, 1, "Password"); userData != nil {
						deviceAccounts[user] = userData[0]
					} else {
						deviceAccounts[user] = ""
					}
				} else {
					if userAuthData.AuthType == authTypeEnum.TOKEN {
						deviceAccounts[user] = s.devicemap[deviceIPAddress].UserLoginInfo[user].Token
					} else if userAuthData.AuthType == authTypeEnum.BASIC {
						deviceAccounts[user] = s.devicemap[deviceIPAddress].UserLoginInfo[user].Password
					}
				}
			}
		}
	}
	return deviceAccounts, http.StatusOK, nil
}
