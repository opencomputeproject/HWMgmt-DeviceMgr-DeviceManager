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
	"encoding/json"
	"fmt"
	"sync"

	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"time"

	importer "devicemanager/proto"
	"github.com/Shopify/sarama"

	logrus "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

//PsmeDefaultPortNumber ...
const PsmeDefaultPortNumber = "8888"

var lock sync.Mutex
var (
	importerTopic = "importer"
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
	importer.RegisterDeviceManagementServer(gserver, s)
	if err := gserver.Serve(listener); err != nil {
		logrus.Errorf("Failed to run gRPC server: %s ", err)
		panic(err)
	}
}
func (s *Server) kafkaCloseProducer() {
	if err := s.dataproducer.Close(); err != nil {
		panic(err)
	}
}
func (s *Server) kafkaInit() {
	logrus.Info("Starting kafka init to Connect to broker: ")
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Compression = sarama.CompressionSnappy
	config.Producer.Flush.Frequency = 500 * time.Millisecond
	config.Producer.Retry.Max = 10
	producer, err := sarama.NewAsyncProducer([]string{GlobalConfig.Kafka}, config)
	if err != nil {
		panic(err)
	}
	s.dataproducer = producer
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
		logrus.Info("Received Event Message ")
		fmt.Printf("%s\n", Body)
		message := &sarama.ProducerMessage{
			Topic: importerTopic,
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

/* validateIPAddress() verifies if the ip and port are valid and already registered then return the truth value of the desired state specified by the following 2 switches,
   wantRegistered: 'true' if the fact of an ip is registered is the desired state
   includePort: 'true' further checks if <ip>:<port#> does exist in the devicemap in case an ip is found registered
*/
func (s *Server) validateIPAddress(ipAddress string) (msg string, ok bool) {
	msg = ""
	ok = false
	if !strings.Contains(ipAddress, ":") {
		logrus.Errorf("Incorrect IP address %s, expected format <ip>:<port #>", ipAddress)
		msg = "Incorrect IP address format (<ip>:<port #>)"
		return
	}
	splits := strings.Split(ipAddress, ":")
	ip, port := splits[0], splits[1]
	if net.ParseIP(ip) == nil {
		// also check to see if it's a valid hostname
		if _, err := net.LookupIP(ip); err != nil {
			logrus.Errorf("Invalid IP address %s", ip)
			msg = "Invalid IP address " + ip
			return
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		logrus.Errorf("Port number %s is not an integer", port)
		msg = "Port number " + port + " needs to be an integer"
		return
	}
	if port != PsmeDefaultPortNumber {
		logrus.Errorf("Port number is %s, it should be %s", port, PsmeDefaultPortNumber)
		msg = "Port number " + port + " should be " + PsmeDefaultPortNumber
		return
	}
	ok = true
	return
}

func (s *Server) initDataPersistence() {
	logrus.Info("Retrieving persisted data")
	subscriptionListPath = pvmount + "/subscriptions"
	if err := os.MkdirAll(subscriptionListPath, 0777); err != nil {
		logrus.Errorf("MkdirAll %s", err)
	} else {
		files, err := ioutil.ReadDir(subscriptionListPath)
		if err != nil {
			logrus.Errorf("ReadDir %s", err)
		} else {
			for _, f := range files {
				b, err := ioutil.ReadFile(path.Join(subscriptionListPath, f.Name()))
				if err != nil {
					logrus.Errorf("Readfile %s", err)
				} else if f.Size() > 0 {
					ip := f.Name()
					d := device{}
					err := json.Unmarshal(b, &d)
					if err != nil {
						logrus.Errorf("Unmarshal %s", err)
						return
					}
					s.devicemap[ip] = &d
					freq := s.devicemap[ip].Freq
					/* if initial interval is 0, create a dummy ticker, which is stopped right away, so getdata is not nil */
					if freq == 0 {
						freq = RfDataCollectDummyInterval
					}
					s.devicemap[ip].Datacollector.getdata = time.NewTicker(time.Duration(freq) * time.Second)
					if s.devicemap[ip].Freq == 0 {
						s.devicemap[ip].Datacollector.getdata.Stop()
					}
					s.devicemap[ip].Datacollector.quit = make(chan bool)
					s.devicemap[ip].Datacollector.getdataend = make(chan bool)
					s.devicemap[ip].Freqchan = make(chan uint32)
					s.devicemap[ip].Datafile = getDataFile(ip)
				}
			}
		}
	}
	deviceDataPath = pvmount + "/device_data"
	if err := os.MkdirAll(deviceDataPath, 0777); err != nil {
		logrus.Errorf("making device data path failed %s", err)
	}
}

func init() {
	Formatter := new(logrus.TextFormatter)
	Formatter.TimestampFormat = "02-01-2006 15:04:05"
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
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	s := Server{
		devicemap:  make(map[string]*device),
		httpclient: client,
	}
	s.kafkaInit()
	go s.runServer()
	go s.startGrpcServer()
	pvmount = os.Getenv("DEVICE_MANAGEMENT_PVMOUNT")
	logrus.Infof("pvmount: %s", pvmount)
	if pvmount != "" {
		logrus.Infof("pvmount enabled")
		s.initDataPersistence()
	} else {
		logrus.Infof("pvmount disabled")
	}
	quit := make(chan os.Signal, 10)
	signal.Notify(quit, os.Interrupt)
	sig := <-quit
	logrus.Infof("Shutting down:%d", sig)
	s.kafkaCloseProducer()
	s.closeDataFiles()
	s.closeDeviceDataFiles()
}
