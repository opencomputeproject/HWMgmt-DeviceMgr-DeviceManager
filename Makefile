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

ROOT_DIR  := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# Variables
VERSION                  ?= $(shell cat ./VERSION)
CONTAINER_NAME           ?= $(notdir $(abspath .))

## Docker related
DOCKER_REGISTRY          ?=
DOCKER_REPOSITORY        ?=
DOCKER_BUILD_ARGS        ?=
DOCKER_TAG               ?= ${VERSION}
DOCKER_IMAGENAME         := device-management:${DOCKER_TAG}

## Docker labels. Only set ref and commit date if committed
DOCKER_LABEL_VCS_URL     ?= $(shell git remote get-url $(shell git remote))
DOCKER_LABEL_VCS_REF     ?= $(shell git diff-index --quiet HEAD -- && git rev-parse HEAD || echo "unknown")
DOCKER_LABEL_COMMIT_DATE ?= $(shell git diff-index --quiet HEAD -- && git show -s --format=%cd --date=iso-strict HEAD || echo "unknown" )
DOCKER_LABEL_BUILD_DATE  ?= $(shell date -u "+%Y-%m-%dT%H:%M:%SZ")

WORKSPACE       ?= $(shell pwd)
DOCKER_VERSION  ?= "17.06"
K8S_VERSION     ?= "1.12.7"
CNI_VERSION     ?= "0.7.5-00"
HELM_VERSION    ?= "2.14.2"
HELM_PLATFORM   ?= "linux-amd64"
HELM_SHA256SUM  ?= "9f50e69cf5cfa7268b28686728ad0227507a169e52bf59c99ada872ddd9679f0"
CALICO_IPAM ?= 192.168.0.0/16
KAFKA_CHART_VERSION  ?= 0.13.3
HELM_GLOBAL_ARGS ?=
LOCAL_DIR=/usr/local
GO_DIR=${LOCAL_DIR}/go
PB_REL=https://github.com/protocolbuffers/protobuf/releases
GRPC_GATEWAY_VERSION=1.16.0
PROTOC_VERSION=3.7.0
PROTOC_SHA256SUM=a1b8ed22d6dc53c5b8680a6f1760a305b33ef471bece482e92728f00ba2a2969
DEVICE_DIR=/var/devices_data

help:
	@echo "Usage: make [<target>]"
	@echo "where available targets are:"
	@echo
	@echo "- If this is the first time you are building, choose those options."
	@echo "install-docker       : Install the docker application. (need to restart system)"
	@echo "k8s                  : Install the kubernetes applications and bring up pods."
	@echo "- Those are operation commands."
	@echo "dm                   : Add device-management pod"
	@echo "clean-dm             : Remove device-management pod"
	@echo "build-dm             : Build device-management docker image"
	@echo "dpv                  : Add device persistent volume"
	@echo "clean-dpv            : Add device persistent volume"
	@echo "reset-pods           : Remove all kubernetes pods (need sudo password)"
	@echo "status               : Look the all Pods status
	@echo "- Addition commands."
	@echo "proto/importer.pb.go : Build importer.pb.go for go build ./.."
	@echo "lint-dockerfile      : Perform static analysis on Dockerfiles"
	@echo "lint-style           : Verify code is properly gofmt-ed"
	@echo "lint-sanity          : Verify that 'go vet' doesn't report any issues"
	@echo "lint-mod             : Verify the integrity of the 'mod' files"
	@echo "lint                 : Shorthand for lint-style & lint-sanity"
	@echo

all: test
k8s: /usr/bin/kubeadm kubeadm /usr/local/bin/helm helm kafka

go-install:
	wget https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz 
	tar xzvf go1.13.3.linux-amd64.tar.gz 
	rm -f go1.13.3.linux-amd64.tar.gz 
	sudo mv go /usr/local
	export GOROOT=${GO_DIR}
	export GOPATH=$(HOME)/app
	export PATH=$(HOME)/app/bin:${GO_DIR}/bin:$$PATH 
	mkdir -p ~/app/bin
	@echo "export GOROOT=${GO_DIR}" >> $(HOME)/.bashrc
	@echo "export GOPATH=$(HOME)/app" >> $(HOME)/.bashrc
	@echo "export PATH=$(HOME)/app/bin:${GO_DIR}/bin:$$PATH" >> $(HOME)/.bashrc
	@echo "!!Please use this command to take effect enviroment variable!!"
	@echo ". $(HOME)/.bashrc"

prereq: /usr/local/bin/protoc
	go get -v google.golang.org/grpc
	go get -v github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	go get -v github.com/golang/protobuf/protoc-gen-go
	go get github.com/sirupsen/logrus
	go get github.com/Shopify/sarama

/usr/local/bin/protoc:
	curl -L -o /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip \
		https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip 
	mkdir -p /tmp/protoc3
	echo "${PROTOC_SHA256SUM}  /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip" | sha256sum -c - \
	 &&  unzip /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /tmp/protoc3 \
	 && sudo mv /tmp/protoc3/bin/* /usr/local/bin/ \
	 && sudo mv /tmp/protoc3/include/* /usr/local/include/
	rm -rf /tmp/protoc3

install-docker:
	sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 0EBFCD88
	sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(shell lsb_release -cs) stable"
	sudo apt update
	sudo apt install -y "docker-ce=${DOCKER_VERSION}*"
	sudo usermod -aG docker $(shell whoami)

/usr/bin/kubeadm:
	curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
	echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /tmp/kubernetes.list
	sudo cp /tmp/kubernetes.list /etc/apt/sources.list.d/kubernetes.list
	sudo apt update
	sudo apt install -y "kubernetes-cni=${CNI_VERSION}"
	sudo apt install -y "kubeadm=${K8S_VERSION}-*" "kubelet=${K8S_VERSION}-*" "kubectl=${K8S_VERSION}-*"

kubeadm:
	sudo swapoff -a
	sudo kubeadm init --pod-network-cidr=${CALICO_IPAM}
	mkdir -p $(HOME)/.kube
	sudo cp -f /etc/kubernetes/admin.conf $(HOME)/.kube/config
	sudo chown $(shell id -u):$(shell id -g) $(HOME)/.kube/config
	@wget https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml
	@sed -i '/CALICO_IPV4POOL_CIDR/!b;n;c\ $(shell printf %12s)\ value: \"${CALICO_IPAM}\"' calico.yaml
	kubectl apply -f https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
	kubectl apply -f ./calico.yaml
	kubectl taint nodes --all node-role.kubernetes.io/master-
	@rm -f calico.yaml

/usr/local/bin/helm:
	curl -L -o /tmp/helm.tgz "https://storage.googleapis.com/kubernetes-helm/helm-v${HELM_VERSION}-${HELM_PLATFORM}.tar.gz"
	echo "${HELM_SHA256SUM}  /tmp/helm.tgz" | sha256sum -c -
	cd /tmp; tar -xzvf helm.tgz; sudo mv ${HELM_PLATFORM}/helm /usr/local/bin/helm
	sudo chmod a+x /usr/local/bin/helm
	@rm -rf /tmp/helm.tgz /tmp/${HELM_PLATFORM}

helm:
	kubectl create serviceaccount --namespace kube-system tiller
	kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
	helm init --service-account tiller
	until helm ls >& /dev/null; \
	do \
		echo "Waiting for Helm to be ready"; \
		sleep 5; \
	done
	helm repo add stable https://charts.helm.sh/stable
	helm repo add incubator https://charts.helm.sh/incubator
	helm repo add cord https://charts.opencord.org
	helm repo update

kafka:
	cd $(WORKSPACE)/helm-charts && \
	helm upgrade --install $(HELM_GLOBAL_ARGS) cord-kafka --version $(KAFKA_CHART_VERSION) -f kafka/kafka-single.yaml incubator/kafka

dm:
	cd $(WORKSPACE)/helm-charts && \
	helm install -n device-management device-management --set images.device_management.pullPolicy='IfNotPresent' --set images.device_management.tag=${VERSION}
	@echo -n "Waiting for loading Device-Manager... "
	@until kubectl get pods --all-namespaces | grep device-management- | awk -F" " '{print $4}' | grep "Running" >& /dev/null; \
	do \
		sleep 2; \
	done
	@echo "Done"

clean-dm:
	@helm del --purge device-management
	@echo -n "Waiting for unloading Device-Manager... "
	@until ! kubectl get pods --all-namespaces | grep device-management- | awk -F" " '{print $4}' >& /dev/null; \
	do \
		sleep 2; \
	done
	@echo "Done"

dpv:
ifeq "$(wildcard $(DEVICE_DIR))" ""
	sudo mkdir -p $(DEVICE_DIR)
endif
	@cd $(WORKSPACE)/helm-charts/storage && \
	helm install -n devices-pv ./local-directory
	@echo -n "Waiting for loading device persistent volume... "
	@until helm ls | grep devices-pv >& /dev/null; \
	do \
		sleep 2; \
	done
	@echo "Done"

clean-dpv:
	sudo rm -rf $(DEVICE_DIR)
	@helm del --purge devices-pv
	@echo -n "Waiting for unloading device persistent volume... "
	@until ! helm ls | grep devices-pv >& /dev/null; \
	do \
		sleep 2; \
	done
	@echo "Done"

reset-pods:
	sudo kubeadm reset -f || true
	sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F && sudo iptables -X
	sudo rm -f /var/lib/cni/networks/pon*/* || true
	sudo rm -f /var/lib/cni/networks/nni*/* || true
	sudo rm -f /var/lib/cni/networks/k8s-pod-network/* || true

proto/importer.pb.go: proto/importer.proto
	mkdir -p proto
	protoc --proto_path=proto \
	-I"${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis" \
	--go_out=plugins=grpc:. \
	proto/importer.proto

build-dm:
	docker build $(DOCKER_BUILD_ARGS) \
	-t ${DOCKER_IMAGENAME} \
	--build-arg org_label_schema_version="${VERSION}" \
	--build-arg org_label_schema_vcs_url="${DOCKER_LABEL_VCS_URL}" \
	--build-arg org_label_schema_vcs_ref="${DOCKER_LABEL_VCS_REF}" \
	--build-arg org_label_schema_build_date="${DOCKER_LABEL_BUILD_DATE}" \
	--build-arg org_opencord_vcs_commit_date="${DOCKER_LABEL_COMMIT_DATE}" \
	-f docker/Dockerfile .

status:
	kubectl get pods --all-namespaces

PATH:=$(GOPATH)/bin:$(PATH)
HADOLINT=$(shell PATH=$(GOPATH):$(PATH) which hadolint)

lint-dockerfile:
ifeq (,$(shell PATH=$(GOPATH):$(PATH) which hadolint))
	mkdir -p $(GOPATH)/bin
	curl -o $(GOPATH)/bin/hadolint -sNSL https://github.com/hadolint/hadolint/releases/download/v1.17.1/hadolint-$(shell uname -s)-$(shell uname -m)
	chmod 755 $(GOPATH)/bin/hadolint
endif
	@echo "Running Dockerfile lint check ..."
	@hadolint $$(find .  -type f -not -path "./vendor/*"  -name "Dockerfile")
	@echo "Dockerfile lint check OK"

lint-style:
ifeq (,$(shell which gofmt))
	go get -u github.com/golang/go/src/cmd/gofmt
endif
	@echo "Running style check..."
	@gofmt_out="$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))" ;\
	if [ ! -z "$$gofmt_out" ]; then \
	  echo "$$gofmt_out" ;\
	  echo "Style check failed on one or more files ^, run 'go fmt' to fix." ;\
	  exit 1 ;\
	fi
	@echo "Style check OK"

lint-sanity:proto/importer.pb.go
	@echo "Running sanity check..."
	@go vet -mod=vendor ./...
	@echo "Sanity check OK"

lint-mod:
	@echo "Running dependency check..."
	@go mod verify
	@echo "Dependency check OK"
lint: lint-style  lint-dockerfile lint-sanity lint-mod

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
