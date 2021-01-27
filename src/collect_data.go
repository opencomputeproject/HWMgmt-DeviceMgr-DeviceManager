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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Shopify/sarama"
	logrus "github.com/sirupsen/logrus"
	"google.golang.org/grpc/status"
)

//RfDataCollectDummyInterval :
const RfDataCollectDummyInterval = 1000

//RfDataCollectThreshold :
const RfDataCollectThreshold = 5

var redfishResources = []string{"/redfish/v1/Chassis/"}
var pvmount = os.Getenv("DEVICE_MANAGEMENT_PVMOUNT")
var subscriptionListPath string
var deviceDataPath string

func (s *Server) updateDataFile(ipAddress string) {
	s.devicemap[ipAddress].DeviceLockFile.Lock()
	defer s.devicemap[ipAddress].DeviceLockFile.Unlock()
	f := s.devicemap[ipAddress].Datafile
	if f != nil {
		b, err := json.Marshal(s.devicemap[ipAddress])
		if err != nil {
			logrus.Errorf("Update data file %s", err)
		} else {
			err := f.Truncate(0)
			if err != nil {
				logrus.Errorf("err Trunate %s", err)
				return
			}
			pos, err := f.Seek(0, 0)
			if err != nil {
				logrus.Errorf("err Seek %s", err)
				return
			}
			fmt.Println("moved back to", pos)
			n, err := f.Write(b)
			if err != nil {
				logrus.Errorf("err wrote %d bytes", n)
				logrus.Errorf("write error to file %s", err)
			}
		}
	} else {
		logrus.Errorf("file handle is nil %s", ipAddress)
	}
}

func (s *Server) saveDeviceDataFile(ipAddress string, data []string) {
	s.devicemap[ipAddress].DeviceDataLockFile.Lock()
	defer s.devicemap[ipAddress].DeviceDataLockFile.Unlock()
	f := s.devicemap[ipAddress].DeviceDatafile
	if f != nil {
		if data == nil {
			logrus.Errorf("saving device data is empty")
		} else {
			for _, str := range data {
				b := []byte(str + "\n")
				n, err := f.Write(b)
				if err != nil {
					logrus.Errorf("err wrote %d bytes", n)
					logrus.Errorf("write error to file %s", err)
				}
			}
		}
	} else {
		logrus.Errorf("file handle is nil %s", ipAddress)
	}
}

func (s *Server) movePositionOfFileToBegin(deviceIPAddress string) error {
	s.devicemap[deviceIPAddress].DeviceDataLockFile.Lock()
	defer s.devicemap[deviceIPAddress].DeviceDataLockFile.Unlock()
	f := s.devicemap[deviceIPAddress].DeviceDatafile
	err := f.Truncate(0)
	if err != nil {
		logrus.Errorf("err Trunate %s", err)
		return err
	}
	_, err = f.Seek(0, 0)
	if err != nil {
		logrus.Errorf("err Seek %s", err)
		return err
	}
	return nil
}

func (s *Server) addPollingRfAPI(deviceIPAddress string, token string, rfAPI string) (statusNum int, err error) {
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
	if userPrivilege != UserPrivileges[0] && userPrivilege != UserPrivileges[1] {
		logrus.Errorf("The user %s privilege could not configure the Redfish API to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user privilege could not configure the Redfish API")
	}
	if len(rfAPI) == 0 {
		logrus.Errorf("The Redfish API is empty !")
		return http.StatusBadRequest, errors.New("The Redfish API is empty !")
	}
	lastByte := rfAPI[len(rfAPI)-1:]
	if lastByte != "/" {
		rfAPI = rfAPI + "/"
	}
	odata := s.getDeviceData(deviceIPAddress, rfAPI, token, 1, "@odata.id")
	if odata == nil {
		logrus.Errorf("The Redfish API is invalid !")
		return http.StatusBadRequest, errors.New("The Redfish API is invalid !")
	}
	for _, api := range s.devicemap[deviceIPAddress].RfAPIList {
		if api == rfAPI {
			logrus.Errorf("The Redfish API is exists !")
			return http.StatusBadRequest, errors.New("The Redfish API is exits !")
		}
	}
	s.devicemap[deviceIPAddress].RfAPIList = append(s.devicemap[deviceIPAddress].RfAPIList, rfAPI)
	s.updateDataFile(deviceIPAddress)
	return http.StatusOK, nil
}

func (s *Server) removePollingRfAPI(deviceIPAddress string, token string, rfAPI string) (statusNum int, err error) {
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
	if userPrivilege != UserPrivileges[0] && userPrivilege != UserPrivileges[1] {
		logrus.Errorf("The user %s privilege could not remove the Redfish API to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user privilege could not configure the Redfish API")
	}
	if len(rfAPI) == 0 {
		logrus.Errorf("The Redfish API is empty !")
		return http.StatusBadRequest, errors.New("The Redfish API is empty !")
	}
	lastByte := rfAPI[len(rfAPI)-1:]
	if lastByte != "/" {
		rfAPI = rfAPI + "/"
	}
	if len(s.devicemap[deviceIPAddress].RfAPIList) != 0 {
		list := s.devicemap[deviceIPAddress].RfAPIList
		var found bool = false
		for key, data := range list {
			if data == rfAPI {
				s.devicemap[deviceIPAddress].RfAPIList = append(list[:key], list[key+1:]...)
				s.updateDataFile(deviceIPAddress)
				found = true
				break
			}
		}
		if found == false {
			logrus.Errorf("The Redfish API does not exist")
			return http.StatusBadRequest, errors.New("The Redfish API does not exist")
		}
	} else {
		logrus.Errorf("It is nothing Redfish API to remove at present")
		return http.StatusBadRequest, errors.New("It is nothing Redfish API to remove at present")
	}
	return http.StatusOK, nil
}

func (s *Server) getRfAPIList(deviceIPAddress string, token string) (list []string, statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return nil, http.StatusBadRequest, errors.New("The user account " + userName + " is not available in deivce")
	}
	if len(s.devicemap) == 0 {
		logrus.Errorf("No any device found")
		return nil, http.StatusBadRequest, errors.New("No any device found")
	}
	return s.devicemap[deviceIPAddress].RfAPIList, http.StatusOK, nil
}

func (s *Server) collectData(ipAddress string) {
	freqchan := s.devicemap[ipAddress].Freqchan
	ticker := s.devicemap[ipAddress].Datacollector.getdata
	donechan := s.devicemap[ipAddress].Datacollector.quit
	for {
		select {
		case freq := <-freqchan:
			ticker.Stop()
			if freq > 0 {
				ticker = time.NewTicker(time.Duration(freq) * time.Second)
				s.devicemap[ipAddress].Datacollector.getdata = ticker
			}
		case err := <-s.dataproducer.Errors():
			logrus.Errorf("Failed to produce message:%s", err)
		case <-ticker.C:
			if s.devicemap[ipAddress].QueryState == true {
				userName := s.devicemap[ipAddress].QueryUser
				done := false
				for _, resource := range s.devicemap[ipAddress].RfAPIList {
					data := s.getDeviceDataByResource(ipAddress, resource, userName)
					if data != nil {
						for index, str := range data {
							str = strings.Replace(str, "\n", "", -1)
							str = strings.Replace(str, " ", "", -1)
							data[index] = str
							str = "Device IP: " + ipAddress + " " + str
							logrus.Infof("collected data  %s", str)
							b := []byte(str)
							msg := &sarama.ProducerMessage{Topic: importerTopic, Value: sarama.StringEncoder(b)}
							s.dataproducer.Input() <- msg
							logrus.Info("Produce message")
						}
						if done == false {
							err := s.movePositionOfFileToBegin(ipAddress)
							if err != nil {
								return
							}
							done = true
						}
						for _, jsonData := range data {
							dataSlice := []string{}
							nowTime := time.Now()
							jsonData = jsonData[1:]
							dataSlice = append(dataSlice, "{\"DataTimestamp\":\""+nowTime.Format("01-02-2006 15:04:05")+"\","+jsonData)
							s.saveDeviceDataFile(ipAddress, dataSlice)
						}
					}
				}
			}
		case <-donechan:
			ticker.Stop()
			logrus.Info("getdata ticker stopped")
			s.devicemap[ipAddress].Datacollector.getdataend <- true
			return
		}
	}
}

func getDataFile(ip string) *os.File {
	logrus.Info("getDataFile")
	if pvmount == "" {
		return nil
	}
	f, err := os.OpenFile(subscriptionListPath+"/"+ip, os.O_CREATE|os.O_RDWR, 0664)
	if err != nil {
		logrus.Errorf("Open device file err %s", err)
	}
	return f
}

func (s *Server) removeDeviceFile(deviceIPAddress string, token string) (err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return errors.New("The user account " + userName + " is not available in deivce")
	}
	if len(s.devicemap) == 0 {
		logrus.Errorf("No any device found")
		return errors.New("No any device found")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] {
		logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
		return errors.New("The user " + userName + " privilege is not administrator")
	}
	s.devicemap[deviceIPAddress].DeviceLockFile.Lock()
	defer s.devicemap[deviceIPAddress].DeviceLockFile.Unlock()
	deviceFile := s.devicemap[deviceIPAddress].Datafile
	if deviceFile != nil {
		logrus.Infof("deleteing file %s", deviceFile.Name())
		err := deviceFile.Close()
		if err != nil {
			logrus.Errorf("error closing device file %s %s", deviceFile.Name(), err)
		}
		err = os.Remove(deviceFile.Name())
		if err != nil {
			logrus.Errorf("error deleting device file %s Error: %s ", deviceFile.Name(), err)
		}
	} else {
		logrus.Errorf("Device file not found (%s)", deviceIPAddress)
	}
	return err
}

func (s *Server) closeDataFiles() {
	for ip := range s.devicemap {
		s.devicemap[ip].Datafile.Close()
	}
}

func getDeviceDataFile(ip string) *os.File {
	logrus.Info("getDeviceDataFile")
	if pvmount == "" {
		return nil
	}
	f, err := os.OpenFile(deviceDataPath+"/"+ip, os.O_CREATE|os.O_RDWR, 0664)
	if err != nil {
		logrus.Errorf("Openfile device data err %s", err)
	}
	return f
}

func (s *Server) removeDeviceDataFile(deviceIPAddress string, token string) (err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return errors.New("The user account " + userName + " does not login to this deivce")
	}
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return errors.New("The user account " + userName + " is not available in deivce")
	}
	if len(s.devicemap) == 0 {
		logrus.Errorf("No any device found")
		return errors.New("No any device found")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] {
		logrus.Errorf("The user %s privilege is not administrator, device %s", userName, deviceIPAddress)
		return errors.New("The user " + userName + " privilege is not administrator")
	}
	s.devicemap[deviceIPAddress].DeviceDataLockFile.Lock()
	defer s.devicemap[deviceIPAddress].DeviceDataLockFile.Unlock()
	deviceDataFile := s.devicemap[deviceIPAddress].DeviceDatafile
	if deviceDataFile != nil {
		logrus.Infof("deleteing device data file %s", deviceDataFile.Name())
		err := deviceDataFile.Close()
		if err != nil {
			logrus.Errorf("error closing device data file %s %s", deviceDataFile.Name(), err)
		}
		err = os.Remove(deviceDataFile.Name())
		if err != nil {
			logrus.Errorf("error deleting device datafile %s Error: %s ", deviceDataFile.Name(), err)
		}
	} else {
		logrus.Errorf("Device data file not found (%s)", deviceIPAddress)
	}
	return err
}

func (s *Server) closeDeviceDataFiles() {
	for ip := range s.devicemap {
		s.devicemap[ip].DeviceDatafile.Close()
	}
}

func (s *Server) startQueryDeviceData(deviceIPAddress string, token string) (statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", token, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account is not available in deivce")
	}
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	s.devicemap[deviceIPAddress].QueryState = true
	s.devicemap[deviceIPAddress].QueryUser = userName
	return http.StatusOK, nil
}

func (s *Server) stopQueryDeviceData(deviceIPAddress string, token string) (statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", token, deviceIPAddress)
		return http.StatusNotFound, errors.New("The user account is not available in deivce")
	}
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this deivce")
	}
	s.devicemap[deviceIPAddress].QueryState = false
	s.devicemap[deviceIPAddress].QueryUser = ""
	return http.StatusOK, nil
}

func (s *Server) setFrequency(deviceIPAddress string, token string, frequency uint32) (statusNum int, err error) {
	userName := s.getUserByToken(deviceIPAddress, token)
	if s.getUserStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s is not available in device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " is not available in device")
	}
	if s.getLoginStatus(deviceIPAddress, token, userName) == false {
		logrus.Errorf("The user account %s does not login to this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user account " + userName + " does not login to this device")
	}
	userPrivilege := s.getUserPrivilege(deviceIPAddress, token, userName)
	if userPrivilege != UserPrivileges[0] && userPrivilege != UserPrivileges[1] {
		logrus.Errorf("The user %s privilege could not configure the frequency of querying data from this device %s", userName, deviceIPAddress)
		return http.StatusBadRequest, errors.New("The user privilege could not configure the frequency of querying data from this device")
	}
	if frequency >= 0 && frequency < RfDataCollectThreshold {
		logrus.WithFields(logrus.Fields{
			"IP address:port": deviceIPAddress}).Info("The frequency value is invalid")
		return http.StatusBadRequest, status.Errorf(http.StatusBadRequest, "The frequency is invalid")
	}
	s.devicemap[deviceIPAddress].Freqchan <- frequency
	s.devicemap[deviceIPAddress].Freq = frequency
	s.updateDataFile(deviceIPAddress)
	return http.StatusOK, nil
}
