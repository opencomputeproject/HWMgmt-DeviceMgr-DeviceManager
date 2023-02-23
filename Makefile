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

# Configure shell
SHELL = bash -eu -o pipefail

# Variables
VERSION                  ?= $(shell cat ./VERSION)

WORKSPACE       ?= $(shell pwd)
LOCAL_DIR=/usr/local
GO_DIR=${LOCAL_DIR}/go
PROTOC_VERSION=3.7.0
PROTOC_SHA256SUM=a1b8ed22d6dc53c5b8680a6f1760a305b33ef471bece482e92728f00ba2a2969
DM_CONFIG_FILE_PATH=${WORKSPACE}/src/config/config.yml
CONFIG_FILE_PATH=${WORKSPACE}/lib-utilities/config/odimra_config.json
GO_BIN_PATH=/usr/local/go/bin

help:
	@echo "Usage: make [<target>]"
	@echo "where available targets are:"
	@echo
	@echo "- Quick installation commands."
	@echo "all                  : Install necessary packages, commands and run Device Manager"
	@echo "buildDeviceMgr       : Build and run Device Manager"
	@echo "buildAndRunODIM      : Build run ODIM's proto files and services"
	@echo
	@echo "- Additional commands."
	@echo "protos               : Build for manager.pb.go file"
	@echo "lintStyle            : Verify code is properly gofmt-ed"
	@echo "lintSanity           : Verify that 'go vet' doesn't report any issues"
	@echo "lintMod              : Verify the integrity of the 'mod' files"
	@echo "lint                 : Shorthand for lintStyle & lintSanity"
	@echo "installRedis         : Download and install Redis"
	@echo "configureRedis       : Setup Redis"
	@echo "installEtcd          : Setup etcd"
	@echo

.PHONY: install

all: init protos buildDeviceMgr buildAndRunODIM

init:
	sudo apt -y update
	sudo apt -y upgrade
	sudo apt -y install git curl unzip
	sudo apt-get install libatomic1

go-install:
	wget https://go.dev/dl/go1.17.10.linux-amd64.tar.gz
	tar xzvf go1.17.10.linux-amd64.tar.gz
	rm -f go1.17.10.linux-amd64.tar.gz
	sudo mv go /usr/local
	export GOROOT=${GO_DIR}
	export GOPATH=$(HOME)/app
	export PATH=$(HOME)/app/bin:${GO_DIR}/bin:$$PATH
	mkdir -p ~/app/bin
	@echo "export GOROOT=${GO_DIR}" >> $(HOME)/.bashrc
	@echo "export GOPATH=$(HOME)/app" >> $(HOME)/.bashrc
	@echo "export PATH=$(HOME)/app/bin:${GO_DIR}/bin:$$PATH" >> $(HOME)/.bashrc
	@echo "!!Please use this command to take effect environment variable!!"
	source $(HOME)/.bashrc

prereq:
	curl -L -o /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip \
		https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip
	mkdir -p /tmp/protoc3
	echo "${PROTOC_SHA256SUM}  /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip" | sha256sum -c - \
	 &&  unzip /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /tmp/protoc3 \
	 && sudo mv /tmp/protoc3/bin/* /usr/local/bin/ \
	 && sudo mv /tmp/protoc3/include/* /usr/local/include/
	rm -rf /tmp/protoc3
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go get -v google.golang.org/grpc
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go install github.com/golang/protobuf/protoc-gen-go@v1.5.2

protos:
	@cd src; \
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app PATH=$(PATH):$(HOME)/app/bin protoc --proto_path=proto \
	--go_out=plugins=grpc:. \
	proto/manager.proto

buildDeviceMgr:
	@echo "Building Device Manager Binary ..."
	@echo "export DM_CONFIG_FILE_PATH=$(DM_CONFIG_FILE_PATH)" >> $(HOME)/.bashrc
	@cd src; \
	${GO_BIN_PATH}/go build -mod=vendor -o ../apps/main .
	export DM_CONFIG_FILE_PATH=$(DM_CONFIG_FILE_PATH)
	./apps/main &>/dev/null &
	@echo "Device Manager is running."

installRedis:
	sudo apt-get install -y pkg-config
	sudo mkdir -p /opt/deviceManager/redis
	wget -qO- https://download.redis.io/releases/redis-6.2.5.tar.gz | sudo tar xzv -C /opt/deviceManager/redis --strip-components=1
	@cd /opt/deviceManager/redis;\
	sudo make

configureRedis:
	wget -P src/config "https://raw.githubusercontent.com/redis/redis/6.2.5/redis.conf"
	/opt/deviceManager/redis/src/redis-server src/config/redis.conf --protected-mode no &
	/opt/deviceManager/redis/src/redis-server src/config/redis.conf --protected-mode no --port 6380 &
	build/createSchema.sh

installEtcd:
	sudo mkdir -p /opt/deviceManager/etcd
	wget -qO- https://github.com/etcd-io/etcd/releases/download/v3.4.15/etcd-v3.4.15-linux-amd64.tar.gz | sudo tar xzv -C /opt/deviceManager/etcd --strip-components=1
	/opt/deviceManager/etcd/etcd --config-file /home/intel/IdeaProjects/HWMgmt-DeviceMgr-DeviceManager/src/config/etcd.conf &

buildAndRunODIM: installRedis configureRedis installEtcd
	build/buildProtoForODIMServices.sh
	build/buildODIMServices.sh
	@echo "export CONFIG_FILE_PATH=$(CONFIG_FILE_PATH)" >> $(HOME)/.bashrc
	export CONFIG_FILE_PATH=$(CONFIG_FILE_PATH)
	build/runODIMServices.sh

PATH:=$(GOPATH)/bin:$(PATH)

lintStyle:
ifeq (,$(shell which gofmt))
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go get -u github.com/golang/go/src/cmd/gofmt
endif
	@echo "Running style check..."
	@gofmt_out="$$(gofmt -l $$(find . -name '*.go' -not -path './src/vendor/*'))" ;\
	if [ ! -z "$$gofmt_out" ]; then \
	  echo "$$gofmt_out" ;\
	  echo "Style check failed on one or more files ^, run 'go fmt' to fix." ;\
	  exit 1 ;\
	fi
	@echo "Style check OK"

lintSanity: protos
	@echo "Running sanity check..."
	@cd src; \
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go vet -mod=vendor ./...
	@echo "Sanity check OK"

lintMod:
	@echo "Running dependency check..."
	@cd src; \
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go mod verify
	@echo "Dependency check OK"
lint: lintStyle lintSanity lintMod

# Rules to automatically install golangci-lint
GOLANGCI_LINT_TOOL?=$(shell which golangci-lint)
ifeq (,$(GOLANGCI_LINT_TOOL))
GOLANGCI_LINT_TOOL=$(GOPATH)/bin/golangci-lint
golangci_lint_tool_install:
	# Same version as installed by Jenkins ci-management
	# Note that install using `go get` is not recommended as per https://github.com/golangci/golangci-lint
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOPATH)/bin v1.17.0
else
golangci_lint_tool_install:
endif

sca: golangci_lint_tool_install
	rm -rf ./sca-report
	@mkdir -p ./sca-report
	$(GOLANGCI_LINT_TOOL) run --out-format junit-xml ./... 2>&1 | tee ./sca-report/sca-report.xml
