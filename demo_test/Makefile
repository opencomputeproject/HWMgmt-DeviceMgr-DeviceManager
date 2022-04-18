# Edgecore DeviceManager
# Copyright 2020-2021 Edgecore Networks, Inc.
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

LOCAL_DIR=/usr/local
GO_DIR=${LOCAL_DIR}/go
GO_BIN_PATH=/usr/local/go/bin

go-install:
	cd .. && make go-install

prereq:
	cd .. && make prereq

demotest: proto/manager.pb.go
	@GOROOT=${GO_DIR} GOPATH=$(HOME)/app GO111MODULE=on ${GO_BIN_PATH}/go build -mod=vendor -v -o $@

proto/importer.pb.go: proto/importer.proto
	cd .. && make src/proto/importer.pb.go
