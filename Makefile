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
	@echo
	@echo "- Additional commands."
	@echo "buildDeviceManager   : Builds Device Manager"
	@echo "protos               : Build for manager.pb.go file"
	@echo "lintStyle            : Verify code is properly gofmt-ed"
	@echo "lintSanity           : Verify that 'go vet' doesn't report any issues"
	@echo "lintMod              : Verify the integrity of the 'mod' files"
	@echo "lint                 : Shorthand for lintStyle & lintSanity"
	@echo "dockerCleanup"		: Kills and removes redis, etcd, device manager containers along with network.
	@echo

.PHONY: install

all: init protos buildDeviceManager buildServices buildDockerImages runDockerImages

dockerCleanup:
	docker kill redis6379 redis6380 device-manager etcd
	docker rm redis6379 redis6380 device-manager etcd
	docker network rm dm-net

runDockerImages:
	docker network create dm-net
	docker run -dp 6379:6379 --name redis6379 --net dm-net redis6379
	docker run -dp 6380:6380 --name redis6380 --net dm-net redis6380
	docker run -h etcd -dp 2379:2379 -p 2380:2380 --name etcd --net dm-net etcd
	docker run -dp 45000:45000 --name device-manager --net dm-net device-manager

buildDockerImages:
	sudo docker build --no-cache -t device-manager -f docker/Dockerfile.DeviceManager .
	sudo docker build --no-cache -t redis6379 -f docker/Dockerfile.Redis.6379 .
	sudo docker build --no-cache -t redis6380 -f docker/Dockerfile.Redis.6380 .
	sudo docker build --no-cache -t etcd -f docker/Dockerfile.Etcd .

init:
	sudo apt -y update
	sudo apt -y upgrade
	sudo apt -y install git curl unzip

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
	@cd svc-device-manager; \
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app PATH=$(PATH):$(HOME)/app/bin protoc --proto_path=proto \
	--go_out=plugins=grpc:. \
	proto/manager.proto

buildDeviceManager:
	@echo "Building Device Manager binary..."
	@cd svc-device-manager; \
	${GO_BIN_PATH}/go build -o ../apps/svc-device-manager .

buildServices:
	build/buildProtoFiles.sh
	build/buildServices.sh

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
