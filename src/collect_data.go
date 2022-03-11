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

const (
	//RfDataCollectDummyInterval ...
	RfDataCollectDummyInterval = 1000
	//RfDataCollectThreshold ...
	RfDataCollectThreshold = 1
)

var (
	//OCP BaseLine Redfish API
	//redfishResources ...
	redfishResources = []string{"/redfish/v1",
		"/redfish/v1/Chassis",
		"/redfish/v1/Managers",
		"/redfish/v1/SessionService",
		"/redfish/v1/SessionService/Sessions",
		"/redfish/v1/AccountService",
		"/redfish/v1/AccountService/Accounts",
		"/redfish/v1/AccountService/Roles",
		"/redfish/v1/AccountService/Roles/Administrator",
		"/redfish/v1/AccountService/Roles/Operator",
		"/redfish/v1/AccountService/Roles/ReadOnly"}
	//pvmount ...
	pvmount = os.Getenv("DEVICE_MANAGEMENT_PVMOUNT")
	//subscriptionListPath ...
	subscriptionListPath string
	//deviceDataPath ...
	deviceDataPath string
)

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

func (s *Server) addPollingRfAPI(deviceIPAddress, authStr, rfAPI string) (statusNum int, err error) {
	if len(rfAPI) == 0 {
		logrus.Errorf(ErrRfAPIEmpty.String())
		return http.StatusBadRequest, errors.New(ErrRfAPIEmpty.String())
	}
	rfAPI = addSlashToTail(rfAPI)
	odata, _, _ := s.getDeviceData(deviceIPAddress, rfAPI, authStr, 1, "@odata.id")
	if odata == nil {
		logrus.Errorf(ErrRfAPIInvalid.String())
		return http.StatusBadRequest, errors.New(ErrRfAPIInvalid.String())
	}
	for _, api := range s.devicemap[deviceIPAddress].RfAPIList {
		api = addSlashToTail(api)
		if api == rfAPI {
			logrus.Errorf(ErrRfAPIExists.String())
			return http.StatusBadRequest, errors.New(ErrRfAPIExists.String())
		}
	}
	s.devicemap[deviceIPAddress].RfAPIList = append(s.devicemap[deviceIPAddress].RfAPIList, rfAPI)
	s.updateDataFile(deviceIPAddress)
	return http.StatusOK, nil
}

func (s *Server) removePollingRfAPI(deviceIPAddress, rfAPI string) (statusNum int, err error) {
	if len(rfAPI) == 0 {
		logrus.Errorf(ErrRfAPIEmpty.String())
		return http.StatusBadRequest, errors.New(ErrRfAPIEmpty.String())
	}
	rfAPI = addSlashToTail(rfAPI)
	if len(s.devicemap[deviceIPAddress].RfAPIList) != 0 {
		list := s.devicemap[deviceIPAddress].RfAPIList
		var found bool
		found = false
		for key, data := range list {
			data = addSlashToTail(data)
			if data == rfAPI {
				s.devicemap[deviceIPAddress].RfAPIList = append(list[:key], list[key+1:]...)
				s.updateDataFile(deviceIPAddress)
				found = true
				break
			}
		}
		if found == false {
			logrus.Errorf(ErrRfAPINotExists.String())
			return http.StatusBadRequest, errors.New(ErrRfAPINotExists.String())
		}
	} else {
		logrus.Errorf(ErrNoRfRemove.String())
		return http.StatusBadRequest, errors.New(ErrNoRfRemove.String())
	}
	return http.StatusOK, nil
}

func (s *Server) clearPollingRfAPI(deviceIPAddress string) (statusNum int, err error) {
	s.devicemap[deviceIPAddress].RfAPIList = []string{}
	s.updateDataFile(deviceIPAddress)
	return http.StatusOK, nil
}

func (s *Server) getRfAPIList(deviceIPAddress string) (list []string, statusNum int, err error) {
	if len(s.devicemap) == 0 {
		logrus.Errorf(ErrNoDevice.String())
		return nil, http.StatusBadRequest, errors.New(ErrNoDevice.String())
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
				done := false
				for _, resource := range s.devicemap[ipAddress].RfAPIList {
					userAuthData := s.devicemap[ipAddress].QueryUser
					if _, ipErr := s.getFunctionsResult("checkIPAddress", ipAddress, "", ""); ipErr != nil {
						continue
					}
					data, err := s.getDeviceDataByResource(ipAddress, resource, userAuthData)
					if data != nil && err == nil {
						for index, str := range data {
							str = strings.Replace(str, "\n", "", -1)
							str = strings.Replace(str, " ", "", -1)
							data[index] = str
							//This is embedded device IP to prefix of messages insteads of sending different Kafka topics
							//str = "Device IP: " + ipAddress + " " + str
							//logrus.Infof("collected data  %s", str)
							logrus.Infof("collected data Device IP: %s %s ", ipAddress, str)
							b := []byte(str)
							if strings.Contains(ipAddress, ":") {
								splits := strings.Split(ipAddress, ":")
								ip, port := splits[0], splits[1]
								ipAddr := ip + "-" + port
								msg := &sarama.ProducerMessage{Topic: managerTopic + "-" + ipAddr, Value: sarama.StringEncoder(b)}
								s.dataproducer.Input() <- msg
							}
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
							dataSlice = append(dataSlice, "{\"DataTimestamp\":\""+nowTime.Format("01-02-2006 15:04:05.000")+"\","+jsonData)
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

func (s *Server) removeDeviceFile(deviceIPAddress string) (err error) {
	if len(s.devicemap) == 0 {
		logrus.Errorf(ErrNoDevice.String())
		return errors.New(ErrNoDevice.String())
	}
	s.devicemap[deviceIPAddress].DeviceLockFile.Lock()
	defer s.devicemap[deviceIPAddress].DeviceLockFile.Unlock()
	deviceFile := s.devicemap[deviceIPAddress].Datafile
	if deviceFile != nil {
		logrus.Infof("deleteing file %s", deviceFile.Name())
		err := deviceFile.Close()
		if err != nil {
			logrus.Errorf(ErrCloseFile.String(deviceFile.Name(), err.Error()))
		}
		err = os.Remove(deviceFile.Name())
		if err != nil {
			logrus.Errorf(ErrDeleteFile.String(deviceFile.Name(), err.Error()))
		}
	} else {
		logrus.Errorf(ErrDeviceFileNotFound.String(deviceIPAddress))
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
		logrus.Errorf(ErrOpenDeviceFailed.String(err.Error()))
	}
	return f
}

func (s *Server) removeDeviceDataFile(deviceIPAddress string) (err error) {
	if len(s.devicemap) == 0 {
		logrus.Errorf(ErrNoDevice.String())
		return errors.New(ErrNoDevice.String())
	}
	s.devicemap[deviceIPAddress].DeviceDataLockFile.Lock()
	defer s.devicemap[deviceIPAddress].DeviceDataLockFile.Unlock()
	deviceDataFile := s.devicemap[deviceIPAddress].DeviceDatafile
	if deviceDataFile != nil {
		logrus.Infof("deleteing device data file %s", deviceDataFile.Name())
		err := deviceDataFile.Close()
		if err != nil {
			logrus.Errorf(ErrCloseDataFile.String(deviceDataFile.Name(), err.Error()))
		}
		err = os.Remove(deviceDataFile.Name())
		if err != nil {
			logrus.Errorf(ErrDeleteDataFile.String(deviceDataFile.Name(), err.Error()))
		}
	} else {
		logrus.Errorf(ErrDeviceDataFileNotFound.String(deviceIPAddress))
	}
	return err
}

func (s *Server) closeDeviceDataFiles() {
	for ip := range s.devicemap {
		s.devicemap[ip].DeviceDatafile.Close()
	}
}

func (s *Server) startQueryDeviceData(deviceIPAddress string, authStr string) (statusNum int, err error) {
	userAuthData := s.getUserAuthData(deviceIPAddress, authStr)
	if (userAuthData == userAuth{}) {
		logrus.Errorf(ErrUserAuthNotFound.String())
		return http.StatusBadRequest, errors.New(ErrUserAuthNotFound.String())
	}
	s.devicemap[deviceIPAddress].QueryState = true
	s.devicemap[deviceIPAddress].QueryUser = userAuthData
	return http.StatusOK, nil
}

func (s *Server) stopQueryDeviceData(deviceIPAddress string) (statusNum int, err error) {
	s.devicemap[deviceIPAddress].QueryState = false
	s.devicemap[deviceIPAddress].QueryUser = userAuth{}
	return http.StatusOK, nil
}

func (s *Server) setFrequency(deviceIPAddress string, frequency uint32) (statusNum int, err error) {
	if frequency >= 0 && frequency < RfDataCollectThreshold {
		logrus.WithFields(logrus.Fields{
			"IP address:port": deviceIPAddress}).Info(ErrFreqValueInvalid.String())
		return http.StatusBadRequest, status.Errorf(http.StatusBadRequest, ErrFreqValueInvalid.String())
	}
	s.devicemap[deviceIPAddress].Freqchan <- frequency
	s.devicemap[deviceIPAddress].Freq = frequency
	s.updateDataFile(deviceIPAddress)
	return http.StatusOK, nil
}
