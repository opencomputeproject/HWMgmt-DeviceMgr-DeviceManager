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
	"crypto/tls"
	"sync"

	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	manager "devicemanager/proto"

	"github.com/Shopify/sarama"

	logrus "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	//lock ...
	lock sync.Mutex
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

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	logrus.Info(" IN Handle Event  ")
	if r.Method == "POST" {
		Body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logrus.Errorf("Error getting HTTP data %s", err)
		}
		defer r.Body.Close()
		message := &sarama.ProducerMessage{
			Topic: managerTopic,
			Value: sarama.StringEncoder(Body),
		}
		s.dataproducer.Input() <- message
	}
}

func (s *Server) runServer() {
	logrus.Info("Starting HTTP Server")
	http.HandleFunc("/", s.handleEvents)
	err := http.ListenAndServeTLS(GlobalConfig.Local, "https-server.crt", "https-server.key", nil)
	if err != nil {
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
	logrus.Info("log Connecting to broker:")
	logrus.Info("log Listening to  http server ")
	//sarama.Logger = log.New()
}

func main() {
	logrus.Info("Starting Device-management Container")
	ParseCommandLine()
	ProcessGlobalOptions()
	ShowGlobalOptions()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	s := Server{
		devicemap: make(map[string]*device),
	}
	go s.runServer()
	go s.startGrpcServer()
	quit := make(chan os.Signal, 10)
	signal.Notify(quit, os.Interrupt)
	sig := <-quit
	logrus.Infof("Shutting down:%d", sig)
}
