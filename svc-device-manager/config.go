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

// Implements global configuration for redfish manager
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	flags "github.com/jessevdk/go-flags"
	logrus "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

//GlobalConfigSpec  ...
type GlobalConfigSpec struct {
	Local     string `yaml:"local"`
	LocalGrpc string `yaml:"localgrpc"`
}

//GlobalConfig ...
var (
	GlobalConfig = GlobalConfigSpec{
		Local:     "0.0.0.0:8080",
		LocalGrpc: "0.0.0.0:50051",
	}
	GlobalCommandOptions = make(map[string]map[string]string)
	GlobalOptions        struct {
		Config    string `short:"c" long:"config" env:"PROXYCONFIG" value-name:"FILE" default:"" description:"Location of proxy config file"`
		Local     string `short:"l" long:"local" default:"" value-name:"SERVER:PORT" description:"IP/Host and port to listen on for http"`
		LocalGrpc string `short:"g" long:"localgrpc" default:"" value-name:"SERVER:PORT" description:"IP/Host and port to listen on for grpc"`
	}
	Debug = log.New(os.Stdout, "DEBUG: ", 0)
	Info  = log.New(os.Stdout, "INFO: ", 0)
	Warn  = log.New(os.Stderr, "WARN: ", 0)
	Error = log.New(os.Stderr, "ERROR: ", 0)
)

func addSlashToTail(data string) string {
	lastByte := data[len(data)-1:]
	if lastByte != "/" {
		data = data + "/"
	}
	return data
}

//JSONToByte ...
func JSONToByte(data interface{}) (retData [][]byte) {
	marshalData, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	marshalDataBytes := bytes.Split(marshalData, []byte(","))
	for index, value := range marshalDataBytes {
		marshalStr := bytes.Split(value, []byte(":"))
		str1 := strings.Trim(string(marshalStr[0]), "\"{}[]")
		str2 := strings.Trim(string(marshalStr[1]), "\"{}[]")
		dataStr := str1 + ":" + str2
		marshalDataBytes[index] = []byte(dataStr)
	}
	return marshalDataBytes
}

//getFunctionsResult ...
func (s *Server) getFunctionsResult(function string, deviceIPAddress string, authStr string, args ...string) (statusCode int, err error) {
	switch function {
	case "checkIPAddress":
		var detectDevice bool
		if args != nil && args[0] != "" {
			detectDevice, _ = strconv.ParseBool(args[0])
		} else {
			detectDevice = DefaultDetectDevice
		}
		if msg, ok := s.validateIPAddress(deviceIPAddress, detectDevice); !ok {
			logrus.WithFields(logrus.Fields{
				"IP address:port": deviceIPAddress}).Errorf(msg)
			return http.StatusBadRequest, errors.New(msg)
		}
	case "checkRegistered":
		if s.vlidateDeviceRegistered(deviceIPAddress) == false {
			logrus.WithFields(logrus.Fields{
				"IP address:port": deviceIPAddress}).Errorf(ErrRegistered.String())
			return http.StatusBadRequest, errors.New(ErrRegistered.String())
		}
	case "checkAccount":
		var userName, password string
		var userAuthData userAuth
		if args != nil && args[0] != "" {
			userName = args[0]
		} else {
			userAuthData = s.getUserAuthData(deviceIPAddress, authStr)
			if (userAuthData == userAuth{}) {
				logrus.Errorf(ErrUserAuthNotFound.String())
				return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
			}
			userName = userAuthData.UserName
		}
		password = ""
		if args != nil && args[1] != "" {
			password = args[1]
		}
		if userName == "" {
			if userAuthData.AuthType != authTypeEnum.NONE { //Authentication Pass
				logrus.Errorf(ErrUserName.String())
				return http.StatusBadRequest, errors.New(ErrUserName.String())
			}
		} else {
			if errRet := s.validateDeviceAccountData(deviceIPAddress, userName, password); errRet != "" {
				logrus.WithFields(logrus.Fields{
					"IP address:port": deviceIPAddress,
					"Username":        userName,
				}).Errorf(errRet)
				return http.StatusBadRequest, errors.New(errRet)
			}
		}
	case "loginStatus":
		var userName string
		var userAuthData userAuth
		if args != nil && args[0] != "" {
			userName = args[0]
			userAuthData = s.getUserAuthData(deviceIPAddress, userName)
			if (userAuthData == userAuth{}) {
				logrus.Errorf(ErrUserAuthNotFound.String())
				return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
			}
			if userAuthData.AuthType == authTypeEnum.BASIC {
				break
			}
		} else {
			userAuthData = s.getUserAuthData(deviceIPAddress, authStr)
			if (userAuthData == userAuth{}) {
				logrus.Errorf(ErrUserAuthNotFound.String())
				return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
			}
			if userAuthData.AuthType == authTypeEnum.BASIC {
				break
			} else {
				userName = userAuthData.UserName
			}
		}
		if userName == "" {
			if userAuthData.AuthType != authTypeEnum.NONE { //Authentication Pass
				logrus.Errorf(ErrUserName.String())
				return http.StatusBadRequest, errors.New(ErrUserName.String())
			}
		} else {
			if s.getLoginStatus(deviceIPAddress, authStr, userName) == false {
				logrus.WithFields(logrus.Fields{
					"IP address:port": deviceIPAddress,
					"Username":        userName,
				}).Errorf(ErrUserLogin.String())
				return http.StatusBadRequest, errors.New(ErrUserLogin.String())
			}
		}
	case "userStatus":
		var userName string
		var userAuthData userAuth
		if args != nil && args[0] != "" {
			userName = args[0]
		} else {
			userAuthData = s.getUserAuthData(deviceIPAddress, authStr)
			if (userAuthData == userAuth{}) {
				logrus.Errorf(ErrUserAuthNotFound.String())
				return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
			}
			userName = userAuthData.UserName
		}
		if userName == "" {
			if userAuthData.AuthType != authTypeEnum.NONE { //Authentication Pass
				logrus.Errorf(ErrUserName.String())
				return http.StatusBadRequest, errors.New(ErrUserName.String())
			}
		} else {
			if s.getUserStatus(deviceIPAddress, authStr, userName) == false {
				logrus.WithFields(logrus.Fields{
					"IP address:port": deviceIPAddress,
					"Username":        userName,
				}).Errorf(ErrUserStatus.String())
				return http.StatusBadRequest, errors.New(ErrUserStatus.String())
			}
		}
	case "userPrivilegeAdmin":
		var userName string
		var userAuthData userAuth
		if args != nil && args[0] != "" {
			userName = args[0]
		} else {
			userAuthData = s.getUserAuthData(deviceIPAddress, authStr)
			if (userAuthData == userAuth{}) {
				logrus.Errorf(ErrUserAuthNotFound.String())
				return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
			}
			userName = userAuthData.UserName
		}
		if userName == "" {
			if userAuthData.AuthType != authTypeEnum.NONE { //Authentication Pass
				logrus.Errorf(ErrUserName.String())
				return http.StatusBadRequest, errors.New(ErrUserName.String())
			}
		} else {
			userPrivilege := s.getUserPrivilege(deviceIPAddress, authStr, userName)
			defineUserPrivilege := s.getDefineUserPrivilege(deviceIPAddress, authStr)[0]
			if userPrivilege != defineUserPrivilege {
				logrus.WithFields(logrus.Fields{
					"IP address:port":        deviceIPAddress,
					"Username":               userName,
					"Privilege":              userPrivilege,
					"Defined User Privilege": defineUserPrivilege,
				}).Errorf(ErrUserAdmin.String())
				return http.StatusBadRequest, errors.New(ErrUserAdmin.String())
			}
		}
	case "userPrivilegeByUser":
		var userName string
		var userAuthData userAuth
		if args != nil && args[0] != "" {
			userName = args[0]
		} else {
			userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
			if (userAuthData == userAuth{}) {
				logrus.Errorf(ErrUserAuthNotFound.String())
				return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
			}
			userName = userAuthData.UserName
		}
		if userName == "" {
			if userAuthData.AuthType != authTypeEnum.NONE { //Authentication Pass
				logrus.Errorf(ErrUserName.String())
				return http.StatusBadRequest, errors.New(ErrUserName.String())
			}
		} else {
			TargetUserPrivilege := s.getUserPrivilege(deviceIPAddress, authStr, args[1])
			userPrivilege := s.getUserPrivilege(deviceIPAddress, authStr, userName)
			privilege := s.getDefineUserPrivilege(deviceIPAddress, authStr)
			if userPrivilege != privilege[0] {
				if (userPrivilege == privilege[1] && TargetUserPrivilege == privilege[0]) ||
					(userPrivilege == privilege[2] && TargetUserPrivilege != privilege[2]) {
					logrus.WithFields(logrus.Fields{
						"IP address:port": deviceIPAddress,
						"Username":        userName,
					}).Errorf(args[2])
					return http.StatusBadRequest, errors.New(args[2])
				}
			}
		}
	case "userPrivilegeOnlyUsers":
		var userName string
		var userAuthData userAuth
		if args != nil && args[0] != "" {
			userName = args[0]
		} else {
			userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
			if (userAuthData == userAuth{}) {
				logrus.Errorf(ErrUserAuthNotFound.String())
				return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
			}
			userName = userAuthData.UserName
		}
		if userName == "" {
			if userAuthData.AuthType != authTypeEnum.NONE { //Authentication Pass
				logrus.Errorf(ErrUserName.String())
				return http.StatusBadRequest, errors.New(ErrUserName.String())
			}
		} else {
			userPrivilege := s.getUserPrivilege(deviceIPAddress, authStr, userName)
			privilege := s.getDefineUserPrivilege(deviceIPAddress, authStr)
			if userPrivilege == privilege[2] {
				logrus.WithFields(logrus.Fields{
					"IP address:port": deviceIPAddress,
					"Username":        userName,
				}).Errorf(args[1])
				return http.StatusBadRequest, errors.New(args[1])
			}
		}
	}
	return
}

//ParseCommandLine ...
func ParseCommandLine() {
	parser := flags.NewNamedParser(path.Base(os.Args[0]),
		flags.HelpFlag|flags.PassDoubleDash|flags.PassAfterNonOption)
	_, err := parser.AddGroup("Global Options", "", &GlobalOptions)
	if err != nil {
		panic(err)
	}
	_, err = parser.ParseArgs(os.Args[1:])
	if err != nil {
		_, ok := err.(*flags.Error)
		if ok {
			real := err.(*flags.Error)
			if real.Type == flags.ErrHelp {
				os.Stdout.WriteString(err.Error() + "\n")
				os.Exit(0)
			}
		}
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err.Error())
		os.Exit(1)
	}
}

//ProcessGlobalOptions ...
func ProcessGlobalOptions() {
	if len(GlobalOptions.Config) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			Warn.Printf("Unable to discover the user's home directory: %s", err)
			home = "~"
		}
		GlobalOptions.Config = filepath.Join(home, ".redfish-manager", "config")
	}
	if info, err := os.Stat(GlobalOptions.Config); err == nil && !info.IsDir() {
		configFile, err := ioutil.ReadFile(GlobalOptions.Config)
		if err != nil {
			Error.Fatalf("Unable to read the configuration file '%s': %s",
				GlobalOptions.Config, err.Error())
		}
		if err = yaml.Unmarshal(configFile, &GlobalConfig); err != nil {
			Error.Fatalf("Unable to parse the configuration file '%s': %s",
				GlobalOptions.Config, err.Error())
		}
	}
	if GlobalOptions.Local != "" {
		GlobalConfig.Local = GlobalOptions.Local
	}
	if GlobalOptions.LocalGrpc != "" {
		GlobalConfig.LocalGrpc = GlobalOptions.LocalGrpc
	}
}

//ShowGlobalOptions ...
func ShowGlobalOptions() {
	log.Printf("Configuration:")
	log.Printf("    Listen Address: %v", GlobalConfig.Local)
	log.Printf("    Grpc Listen Address: %v", GlobalConfig.LocalGrpc)
}
