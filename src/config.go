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

// Implements global configuration for redfish importer
package main

import (
	"fmt"
	flags "github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type OutputType uint8

type GlobalConfigSpec struct {
	Kafka     string `yaml:"kafka"`
	Local     string `yaml:"local"`
	LocalGrpc string `yaml:"localgrpc"`
}

var (
	CharReplacer = strings.NewReplacer("\\t", "\t", "\\n", "\n")

	GlobalConfig = GlobalConfigSpec{
		Kafka:     "cord-kafka.default.svc.cluster.local:9092",
		Local:     "0.0.0.0:8080",
		LocalGrpc: "0.0.0.0:50051",
	}

	GlobalCommandOptions = make(map[string]map[string]string)

	GlobalOptions struct {
		Config    string `short:"c" long:"config" env:"PROXYCONFIG" value-name:"FILE" default:"" description:"Location of proxy config file"`
		Kafka     string `short:"k" long:"kafka" default:"" value-name:"SERVER:PORT" description:"IP/Host and port of Kafka"`
		Local     string `short:"l" long:"local" default:"" value-name:"SERVER:PORT" description:"IP/Host and port to listen on for http"`
		LocalGrpc string `short:"g" long:"localgrpc" default:"" value-name:"SERVER:PORT" description:"IP/Host and port to listen on for grpc"`
	}

	Debug = log.New(os.Stdout, "DEBUG: ", 0)
	Info  = log.New(os.Stdout, "INFO: ", 0)
	Warn  = log.New(os.Stderr, "WARN: ", 0)
	Error = log.New(os.Stderr, "ERROR: ", 0)
)

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

func ProcessGlobalOptions() {
	if len(GlobalOptions.Config) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			Warn.Printf("Unable to discover the user's home directory: %s", err)
			home = "~"
		}
		GlobalOptions.Config = filepath.Join(home, ".redfish-importer", "config")
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

	if GlobalOptions.Kafka != "" {
		GlobalConfig.Kafka = GlobalOptions.Kafka
	}
	if GlobalOptions.Local != "" {
		GlobalConfig.Local = GlobalOptions.Local
	}
	if GlobalOptions.LocalGrpc != "" {
		GlobalConfig.LocalGrpc = GlobalOptions.LocalGrpc
	}
}

func ShowGlobalOptions() {
	log.Printf("Configuration:")
	log.Printf("    Kafka: %v", GlobalConfig.Kafka)
	log.Printf("    Listen Address: %v", GlobalConfig.Local)
	log.Printf("    Grpc Listen Address: %v", GlobalConfig.LocalGrpc)
}
