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
	"devicemanager/config"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	manager "devicemanager/proto"

	logrus "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	//managerTopic ...
	managerTopic = "manager"
)

//NewGrpcServer ...
func NewGrpcServer(grpcport string) (l net.Listener, g *grpc.Server, e error) {
	logrus.Infof("Listening %s\n", grpcport)
	g = grpc.NewServer()
	l, e = net.Listen("tcp", grpcport)
	return
}
func (s *Server) startGrpcServer() {
	logrus.Info("starting gRPC Server")
	listener, gserver, err := NewGrpcServer(GlobalConfig.LocalGrpc)
	if err != nil {
		logrus.Errorf("Failed to create gRPC server: %s ", err)
		panic(err)
	}
	s.gRPCserver = gserver
	manager.RegisterDeviceManagementServer(gserver, s)
	if err := gserver.Serve(listener); err != nil {
		logrus.Errorf("Failed to run gRPC server: %s ", err)
		panic(err)
	}
}

func (s *Server) vlidateDeviceRegistered(deviceIPAddress string) bool {
	if len(s.devicemap) != 0 {
		for device := range s.devicemap {
			if strings.HasPrefix(device, deviceIPAddress) {
				return true
			}
		}
	}
	return false
}

func detectNetwork(ip string, port string) bool {
	address := net.JoinHostPort(ip, port)
	// 3 second timeout
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return false
	}
	if conn != nil {
		_ = conn.Close()
	} else {
		return false
	}
	return true
}

/* validateIPAddress() verifies if the ip and port are valid and already registered then return the truth value of the desired state specified by the following 2 switches,
   wantRegistered: 'true' if the fact of an ip is registered is the desired state
   includePort: 'true' further checks if <ip>:<port#> does exist in the devicemap in case an ip is found registered
*/
func (s *Server) validateIPAddress(ipAddress string, detectDevice bool) (msg string, ok bool) {
	msg = ""
	ok = false
	if !strings.Contains(ipAddress, ":") {
		logrus.Errorf("Incorrect IP address %s, expected format <ip>:<port #>", ipAddress)
		msg = "Incorrect IP address format (<ip>:<port #>)"
		return
	}
	splits := strings.Split(ipAddress, ":")
	ip, port := splits[0], splits[1]
	if _, err := net.LookupIP(ip); err != nil || net.ParseIP(ip) == nil {
		logrus.Errorf("Invalid IP address %s", ip)
		msg = "Invalid IP address " + ip
		return
	}
	if _, err := strconv.Atoi(port); err != nil {
		logrus.Errorf("Port number %s is not an integer", port)
		msg = "Port number " + port + " needs to be an integer"
		return
	}
	if detectDevice == true {
		if detectNetwork(ip, port) == false {
			logrus.Errorf("The device %s:%s could not reach", ip, port)
			msg = "The device " + ip + ":" + port + " could not reach"
			return
		}
	}
	ok = true
	return
}

func init() {
	Formatter := new(logrus.TextFormatter)
	Formatter.TimestampFormat = "02-01-2006 15:04:05.000000"
	Formatter.FullTimestamp = true
	logrus.SetFormatter(Formatter)
	logrus.SetLevel(logrus.DebugLevel)
}

func main() {
	// Verify user ID.
	if os.Geteuid() == 0 {
		logrus.Fatal("Device Manager should not run with root privileges")
	}
	logrus.Info("Starting Device Manager")

	if _, err := config.LoadConfiguration(); err != nil {
		logrus.Fatal("error while loading config", err)
	} else {
		ParseCommandLine()
		ProcessGlobalOptions()
		ShowGlobalOptions()
		s := Server{
			devicemap: make(map[string]*device),
		}
		go s.startGrpcServer()
		quit := make(chan os.Signal, 10)
		signal.Notify(quit, os.Interrupt)
		sig := <-quit
		logrus.Infof("Shutting down:%d", sig)
	}
}
