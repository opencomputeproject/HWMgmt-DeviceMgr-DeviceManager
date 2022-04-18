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

//errorIndex - Custom type to hold value for error ranging 1 ~ end
type errorIndex int

// Declare related constants for each error starting with index 1
const (
	ErrRegistered errorIndex = iota + 1 // Index = 1
	ErrHasRegistered
	ErrDeviceData
	ErrUserName
	ErrUserLogin
	ErrUserStatus
	ErrUserAdmin
	ErrUserPrivilege
	ErrUserHigherPrivilege
	ErrSessionExists
	ErrSessionFailed
	ErrSessionNotSet
	ErrSessionTimeout
	ErrLoginFailed
	ErrDeleteLoginFailed
	ErrUserIsBasicAuth
	ErrChangePwdFailed
	ErrDeleteUserAccount
	ErrDeleteUserSelf
	ErrCreateUserAccount
	ErrUsername
	ErrPassword
	ErrUserPrivilegeInvalid
	ErrUsernameLength
	ErrUserPwdLength
	ErrAccountData
	ErrRfAPIEmpty
	ErrRfAPIInvalid
	ErrRfAPIExists
	ErrRfAPINotExists
	ErrNoRfRemove
	ErrNoDevice
	ErrCloseFile
	ErrDeleteFile
	ErrDeviceFileNotFound
	ErrOpenDeviceFailed
	ErrCloseDataFile
	ErrDeleteDataFile
	ErrDeviceDataFileNotFound
	ErrQueryNotSupport
	ErrFreqValueInvalid
	ErrHTTPDataUpdate
	ErrHTTPGetBody
	ErrHTTPBodyEmpty
	ErrHTTPApplicationEmpty
	ErrHTTPTypeEmpty
	ErrHTTPType
	ErrHTTPGetDataFailed
	ErrHTTPPostDataFailed
	ErrHTTPPatchDataFailed
	ErrHTTPDeleteDataFailed
	ErrHTTPDecodeBodyFailed
	ErrHTTPReadBodyFailed
	ErrHTTPDataUpdateFailed
	ErrUnsupportHTTPStateCode
	ErrHTTPRedirectTimeOut
	ErrHTTPRedirectGetFailed
	ErrConvertData
	ErrDataToFirstPos
	ErrGetDeviceData
	ErrFailedToFindData
	ErrPostDeviceData
	ErrDeleteDeviceData
	ErrPatchDeviceData
	ErrUnsupportHTTPMethod
	ErrGetLogServiceStateFailed
	ErrGetLogServiceRfAPI
	ErrLogServiceInTheState
	ErrSetLogServiceFailed
	ErrResetLogDataFailed
	ErrSWTypeEmpty
	ErrSWTypeInvalid
	ErrSWDataEmpty
	ErrNotsupportUEFI
	ErrNotsufficientMemStorage
	ErrSWUpdateInProcess
	ErrSWUpdateNotImplemented
	ErrGetResetTypeFailed
	ErrResetTypeEmpty
	ErrResetTypeNotsupport
	ErrResetSystemFailed
	ErrGetTemperDataFailed
	ErrConvertTemperDataFailed
	ErrEventTemperInvalid
	ErrSetEventTemperFailed
	ErrUserAuthNotFound
)

// String - Creating error descriptions - give the type a String function
func (e errorIndex) String(args ...string) string {
	//Assume the lengith of the argruments is 3
	var argsStrs []string
	argsStrs = make([]string, 3)
	for id, argsStr := range args {
		argsStrs[id] = argsStr
	}
	return [...]string{
		/*ErrRegistered*/ "This device is not registered",
		/*ErrHasRegistered*/ "Device ip " + argsStrs[0] + " already registered",
		/*ErrDeviceData*/ "The device data error",
		/*ErrUserName*/ "Could not find the user",
		/*ErrUserLogin*/ "The user account does not login to this device",
		/*ErrUserStatus*/ "Please check this user account in this device",
		/*ErrUserAdmin*/ "The user privilege is not administrator",
		/*ErrUserPrivilege*/ "The user privilege could not configure this action to the device",
		/*ErrUserHigherPrivilege*/ "The user privilege could not configure this action than other higher user",
		/*ErrSessionExists*/ "The session service was enabled on the device " + argsStrs[0] + ". Please login device first and assige the token",
		/*ErrSessionFailed*/ "The session service is not enable to configure on device " + argsStrs[0] + " now, status code " + argsStrs[1],
		/*ErrSessionNotSet*/ "The session service does not enable yet, device " + argsStrs[0],
		/*ErrSessionTimeout*/ "The seesion timeout has to over " + argsStrs[0],
		/*ErrLoginFailed*/ "Failed to login device, status code " + argsStrs[0],
		/*ErrDeleteLoginFailed*/ "Failed to delete login session id " + argsStrs[0] + ", status code " + argsStrs[1],
		/*ErrUserIsBasicAuth*/ "The user is belongings to Basic Authentication",
		/*ErrChangePwdFailed*/ "Failed to change device user (" + argsStrs[0] + ") password, status code " + argsStrs[1],
		/*ErrDeleteUserAccount*/ "Failed to delete device account " + argsStrs[0] + ", status code " + argsStrs[1],
		/*ErrDeleteUserSelf*/ "The user (" + argsStrs[0] + ") could be not removed itself",
		/*ErrCreateUserAccount*/ "Failed to create device account " + argsStrs[0] + ", status code " + argsStrs[1],
		/*ErrUsername*/ "The username " + argsStrs[0] + " is invalid",
		/*ErrPassword*/ "The user password is invalid",
		/*ErrUserPrivilegeInvalid*/ "The user " + argsStrs[0] + " privilege is invalid",
		/*ErrUsernameLength*/ "Device " + argsStrs[0] + ": " + "The device user name length has to below " + argsStrs[1] + " characters",
		/*ErrUserPwdLength*/ "Device " + argsStrs[0] + ": " + "The device user password length has to below " + argsStrs[1] + " characters",
		/*ErrAccountData*/ "The account data error",
		/*ErrRfAPIEmpty*/ "The Redfish API is empty",
		/*ErrRfAPIInvalid*/ "The Redfish API is invalid",
		/*ErrRfAPIExists*/ "The Redfish API is exists",
		/*ErrRfAPINotExists*/ "The Redfish API does not exist",
		/*ErrNoRfRemove*/ "Could not find Redfish API to remove at present",
		/*ErrNoDevice*/ "No device found",
		/*ErrCloseFile*/ "Closing device file " + argsStrs[0] + ", Error: " + argsStrs[1],
		/*ErrDeleteFile*/ "Deleting device file " + argsStrs[0] + ", Error: " + argsStrs[1],
		/*ErrDeviceFileNotFound*/ "Device file not found (" + argsStrs[0] + ")",
		/*ErrOpenDeviceFailed*/ "Open file device data error: " + argsStrs[0],
		/*ErrCloseDataFile*/ "Closing device data file " + argsStrs[0] + ", Error: " + argsStrs[1],
		/*ErrDeleteDataFile*/ "Deleting device data file " + argsStrs[0] + ", Error: " + argsStrs[1],
		/*ErrDeviceDataFileNotFound*/ "Device data file not found (" + argsStrs[0] + ")",
		/*ErrQueryNotSupport*/ "The device model (" + argsStrs[0] + ") does not support periodic querying device data",
		/*ErrFreqValueInvalid*/ "The frequency value is invalid",
		/*ErrHTTPDataUpdate*/ "HTTP Data update error",
		/*ErrHTTPGetBody*/ "Failed to get the HTTP body, status code  " + argsStrs[0],
		/*ErrHTTPBodyEmpty*/ "http body data is empty",
		/*ErrHTTPApplicationEmpty*/ "http Content-Type is empty",
		/*ErrHTTPTypeEmpty*/ "http conntion type is empty",
		/*ErrHTTPType*/ "http conneciton type error",
		/*ErrHTTPGetDataFailed*/ "http get data error, status code: " + argsStrs[0],
		/*ErrHTTPPostDataFailed*/ "http post data error, " + argsStrs[0],
		/*ErrHTTPPatchDataFailed*/ "http patch data error, " + argsStrs[0],
		/*ErrHTTPDeleteDataFailed*/ "http delete data error, " + argsStrs[0],
		/*ErrHTTPDecodeBodyFailed*/ "decode http body error, " + argsStrs[0],
		/*ErrHTTPReadBodyFailed*/ "Read HTTP boday error, " + argsStrs[0],
		/*ErrHTTPDataUpdateFailed*/ "HTTP Data update error",
		/*ErrUnsupportHTTPStateCode*/ "Unsupport HTTP status code " + argsStrs[0],
		/*ErrHTTPRedirectTimeOut*/ "HTTP stopped after 10 redirects",
		/*ErrHTTPRedirectGetFailed*/ "HTTP method (" + argsStrs[0] + ") redirection Error: " + argsStrs[1],
		/*ErrConvertData*/ "Covert data to array error, Error: " + argsStrs[0],
		/*ErrDataToFirstPos*/ "Device data file could not move to first position",
		/*ErrGetDeviceData*/ "Failed to get device data, status code " + argsStrs[0],
		/*ErrFailedToFindData*/ "Failed to find the data from the Redfish API",
		/*ErrPostDeviceData*/ "Failed to post data to device, status code " + argsStrs[0],
		/*ErrDeleteDeviceData*/ "Failed to delete device data, status code " + argsStrs[0] + ", delete data: " + argsStrs[1],
		/*ErrPatchDeviceData*/ "Failed to patch device data, status code " + argsStrs[0] + ", delete data: " + argsStrs[1],
		/*ErrUnsupportHTTPMethod*/ "Unsupported HTTP method (" + argsStrs[0] + ")",
		/*ErrGetLogServiceStateFailed*/ "Failed to get device log service state",
		/*ErrGetLogServiceRfAPI*/ "Failed to get Log service Redfish API",
		/*ErrLogServiceInTheState*/ "The log service state has in the " + argsStrs[0],
		/*ErrSetLogServiceFailed*/ "Failed to set log service state, status code " + argsStrs[0],
		/*ErrResetLogDataFailed*/ "Failed to reset log data, status code " + argsStrs[0],
		/*ErrSWTypeEmpty*/ "The software update type is empty",
		/*ErrSWTypeInvalid*/ "The software update type is invalid",
		/*ErrSWDataEmpty*/ "The software update data is empty",
		/*ErrNotsupportUEFI*/ "Device does not support UEFI environment",
		/*ErrNotsufficientMemStorage*/ "Device does not have sufficient Memory/Storage",
		/*ErrSWUpdateInProcess*/ "The update request is processing, This is forbidden to request again",
		/*ErrSWUpdateNotImplemented*/ "The software update does not implement in the device",
		/*ErrGetResetTypeFailed*/ "Failed to get the device reset type",
		/*ErrResetTypeEmpty*/ "The device system reset type is empty",
		/*ErrResetTypeNotsupport*/ "The device reset type (" + argsStrs[0] + ") does not support, The supported reset type are \"" + argsStrs[1] + "\"",
		/*ErrResetSystemFailed*/ "Failed to reset system, status code " + argsStrs[0],
		/*ErrGetTemperDataFailed*/ "Failed to get device temperature data",
		/*ErrConvertTemperDataFailed*/ "Failed to convert temperature data",
		/*ErrEventTemperInvalid*/ "The device event temperature is invalid",
		/*ErrSetEventTemperFailed*/ "Failed to configure device event temperature, status code " + argsStrs[0],
		/*ErrUserAuthNotFound*/ "The user authentication data does not found",
	}[e-1]
}

// ErrorIndex - Returning error code - give the type a ErrorIndex function
func (e errorIndex) ErrorCode() int32 {
	return int32(^uint32(int32(e) - 1))
}
