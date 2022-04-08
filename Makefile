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
CALICO_NET = $(shell \
docker_net_172="$(shell ip route | grep ' dev ' | grep '^172.')"; \
if [ -z "$$docker_net_172" ]; then \
echo "172.20.0.0/16"; \
else \
docker_net_192="$(shell ip route | grep ' dev ' | grep '^192.')"; \
if [ -z "$$docker_net_192" ]; then \
echo "192.168.0.0/16"; \
else \
docker_net_10="$(shell ip route | grep ' dev ' | grep '^10.')"; \
if [ -z "$$docker_net_10" ]; then \
echo "10.10.0.0/16"; \
fi \
fi \
fi \
)

WORKSPACE       ?= $(shell pwd)
DOCKER_VERSION  ?= "5:20.10.6"
K8S_VERSION     ?= "1.21.0"
CNI_VERSION     ?= "0.8.7-00"
HELM_VERSION    ?= "v3.5.4"
CALICO_IPAM ?= 192.168.0.0/16
KAFKA_CHART_VERSION  ?= 0.21.5
KAFKA_SERVICE_URL=cord-kafka-0.cord-kafka-headless.manager.svc.cluster.local
LOCAL_DIR=/usr/local
GO_DIR=${LOCAL_DIR}/go
PROTOC_VERSION=3.7.0
PROTOC_SHA256SUM=a1b8ed22d6dc53c5b8680a6f1760a305b33ef471bece482e92728f00ba2a2969
DEVICE_DIR=/var/devices_data
GO_BIN_PATH=/usr/local/go/bin
CHART_STATUS = $(shell \
if [ ! -z "`which helm`" -a ! -z "`netstat -ntal|grep LISTEN|grep :6443`" ]; then \
helm ls -n manager -q -l name=$1; \
fi \
)

help:
	@echo "Usage: make [<target>]"
	@echo "where available targets are:"
	@echo
	@echo "- Quickly Installaiton commands."
	@echo "all                  : Install necessory packages and commands and bring up/build all containers."
	@echo "install              : Reinstall all containers."
	@echo
	@echo "- If this is the first time you are building, choose those options."
	@echo "/usr/bin/docker      : Install the docker application."
	@echo "k8s                  : Install the kubernetes applications and bring up pods."
	@echo
	@echo "- Those are operation commands."
	@echo "dm                   : Add device-management pod"
	@echo "clean-dm             : Remove device-management pod"
	@echo "build-dm             : Build device-management docker image"
	@echo "dpv                  : Add device persistent volume"
	@echo "clean-dpv            : Add device persistent volume"
	@echo "reset-pods           : Remove all kubernetes pods (need sudo password)"
	@echo "status               : Look the all Pods status"
	@echo
	@echo "- Addition commands."
	@echo "protos               : Build for manager.pb.go file"
	@echo "lint-dockerfile      : Perform static analysis on Dockerfiles"
	@echo "lint-style           : Verify code is properly gofmt-ed"
	@echo "lint-sanity          : Verify that 'go vet' doesn't report any issues"
	@echo "lint-mod             : Verify the integrity of the 'mod' files"
	@echo "lint                 : Shorthand for lint-style & lint-sanity"
	@echo

.PHONY: install

all: init /usr/bin/docker go-install prereq install
install: reset-pods install_all
k8s: restart-docker resolv-file /usr/bin/kubeadm kubeadm /usr/local/bin/helm helm kafka

install_all:
	make k8s build-dm dpv dm status

init:
	sudo apt -y update
	sudo apt -y upgrade
	sudo apt -y install git curl unzip

go-install:
	wget https://go.dev/dl/go1.16.10.linux-amd64.tar.gz
	tar xzvf go1.16.10.linux-amd64.tar.gz
	rm -f go1.16.10.linux-amd64.tar.gz
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
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go get -v google.golang.org/grpc
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go get -v github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go get -v github.com/golang/protobuf/protoc-gen-go
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go get github.com/sirupsen/logrus

/usr/local/bin/protoc:
	curl -L -o /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip \
		https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip 
	mkdir -p /tmp/protoc3
	echo "${PROTOC_SHA256SUM}  /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip" | sha256sum -c - \
	 &&  unzip /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /tmp/protoc3 \
	 && sudo mv /tmp/protoc3/bin/* /usr/local/bin/ \
	 && sudo mv /tmp/protoc3/include/* /usr/local/include/
	rm -rf /tmp/protoc3

/usr/bin/docker:
	sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 0EBFCD88
	sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(shell lsb_release -cs) stable"
	sudo apt update
	sudo apt install -y "docker-ce=${DOCKER_VERSION}*"
	sudo usermod -aG docker $(shell whoami)
	sudo chmod 777 /var/run/docker.sock

/usr/bin/kubeadm:
	curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
	echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /tmp/kubernetes.list
	sudo cp /tmp/kubernetes.list /etc/apt/sources.list.d/kubernetes.list
	sudo apt update
	sudo apt install -y "kubernetes-cni=${CNI_VERSION}"
	sudo apt install -y "kubeadm=${K8S_VERSION}-*" "kubelet=${K8S_VERSION}-*" "kubectl=${K8S_VERSION}-*"

kubeadm: /usr/bin/kubeadm
	$(eval CALICO_IPAM:=$(call CALICO_NET))
	sudo swapoff -a
	sudo kubeadm init --pod-network-cidr=${CALICO_IPAM}
	mkdir -p $(HOME)/.kube
	sudo cp -f /etc/kubernetes/admin.conf $(HOME)/.kube/config
	sudo chown $(shell id -u):$(shell id -g) $(HOME)/.kube/config
	@wget --no-check-certificate https://docs.projectcalico.org/v3.10/manifests/calico.yaml
	@sed -i '/CALICO_IPV4POOL_CIDR/!b;n;c\ $(shell printf %12s)\ value: \"${CALICO_IPAM}\"' calico.yaml
	kubectl apply -f https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
	kubectl apply -f ./calico.yaml
	kubectl taint nodes --all node-role.kubernetes.io/master-
	@rm -f calico.yaml
	sudo sysctl -w net.ipv4.conf.all.rp_filter=1
	kubectl -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true
	@echo -n "Waiting for loading Calico... "
	@until kubectl -n kube-system get pods | grep calico-kube-controllers | awk -F" " '{print $3}' | grep "Running" >& /dev/null && \
		kubectl -n kube-system get pods | grep calico-node | awk -F" " '{print $3}' | grep "Running" >& /dev/null; \
	do \
		sleep 2; \
	done

/usr/local/bin/helm:
	wget https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
	@chmod +x get-helm-3
	./get-helm-3 --version ${HELM_VERSION}
	@rm -f get-helm-3

helm: /usr/local/bin/helm
	helm repo add stable https://charts.helm.sh/stable --force-update
	helm repo add incubator https://charts.helm.sh/incubator --force-update
	helm repo update

kafka:
	cd $(WORKSPACE)/helm-charts && \
	helm upgrade --version $(KAFKA_CHART_VERSION) --install --create-namespace -n manager -f kafka/kafka-single.yaml cord-kafka incubator/kafka
	@until kubectl -n manager get pods | grep zookeeper | awk -F" " '{print $3}' | grep "Running" >& /dev/null; \
	do \
		echo "Waiting for Zookeeper to be ready"; \
		sleep 5; \
	done
	@until kubectl -n manager get pods | grep cord-kafka-0 | awk -F" " '{print $3}' | grep "Running" >& /dev/null; \
	do \
		echo "Waiting for Kafka to be ready"; \
		sleep 5; \
	done

dm: dpv
ifeq (,$(call CHART_STATUS,"device-management"))
	cd $(WORKSPACE)/helm-charts && \
	helm upgrade -n manager --install --create-namespace --set images.device_management.pullPolicy='IfNotPresent' --set images.device_management.tag=${VERSION} device-management device-management
	@echo -n "Waiting for loading Device-Manager... "
	@until kubectl -n manager exec `kubectl -n manager get pods -o=jsonpath='{.items[2].metadata.name}'` -- \
		nc -z -v $(KAFKA_SERVICE_URL) 9092 2>&1 | grep "open" >& /dev/null; \
	do \
		sleep 2; \
	done
	@echo "Done"
endif

clean-dm: clean-dpv
ifneq (,$(call CHART_STATUS,"device-management"))
	@helm -n manager uninstall device-management
	@echo -n "Waiting for unloading Device-Manager... "
	@until ! kubectl -n manager get pods | grep device-management- >& /dev/null; \
	do \
		sleep 2; \
	done
	@echo "Done"
endif

dpv:
ifeq (,$(call CHART_STATUS,"devices-pv"))
ifeq "$(wildcard $(DEVICE_DIR))" ""
	sudo mkdir -p $(DEVICE_DIR)
endif
	@cd $(WORKSPACE)/helm-charts/storage && \
	helm -n manager install devices-pv ./local-directory
	@echo -n "Waiting for loading device persistent volume... "
	@until helm -n manager ls -q | grep devices-pv >& /dev/null; \
	do \
		sleep 2; \
	done
	@echo "Done"
endif

clean-dpv:
ifneq (,$(call CHART_STATUS,"devices-pv"))
	sudo rm -rf $(DEVICE_DIR)
	@helm -n manager uninstall devices-pv
	@echo -n "Waiting for unloading device persistent volume... "
	@until ! helm -n manager ls -q | grep devices-pv >& /dev/null; \
	do \
		sleep 2; \
	done
	@echo "Done"
endif

clean-kafka:
ifneq (,$(call CHART_STATUS,"cord-kafka"))
	@helm -n manager uninstall cord-kafka; \
	sleep 2
	@until ! kubectl -n manager get pods | grep cord-kafka-0 >& /dev/null; \
	do \
		sleep 5; \
	done
	@until ! kubectl -n manager get pods | grep zookeeper >& /dev/null; \
	do \
		sleep 5; \
	done
	@echo "Done"
endif

clean: clean-kafka clean-dpv clean-dm

reset-pods: /usr/bin/kubeadm /usr/bin/docker clean
	sudo kubeadm reset -f || true
	sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F && sudo iptables -X
	make restart-docker

protos: src/proto/manager.pb.go

src/proto/manager.pb.go:
	@cd src; \
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app PATH=$(PATH):$(HOME)/app/bin protoc --proto_path=proto \
	--go_out=plugins=grpc:. \
	proto/manager.proto

device-manager-binary: protos
	@echo "Building Device Manager Binary ..."
	@cd src; \
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app GO111MODULE=on CGO_ENABLED=0 GOOS=linux ${GO_BIN_PATH}/go build -mod=vendor -o ../apps/main .

build-dm: resolv-file device-manager-binary
	docker build $(DOCKER_BUILD_ARGS) \
	-t ${DOCKER_IMAGENAME} \
	--build-arg org_label_schema_version="${VERSION}" \
	--build-arg org_label_schema_vcs_url="${DOCKER_LABEL_VCS_URL}" \
	--build-arg org_label_schema_vcs_ref="${DOCKER_LABEL_VCS_REF}" \
	--build-arg org_label_schema_build_date="${DOCKER_LABEL_BUILD_DATE}" \
	-f docker/Dockerfile .

status:
	kubectl get pods --all-namespaces -o wide

resolv-file:
	@chk_nameserver="$(shell cat /etc/resolv.conf | grep 'nameserver 8.8.8.8')"; \
	if [ -z "$$chk_nameserver" ]; then \
		sudo sh -c "echo nameserver 8.8.8.8 > /etc/resolv.conf"; \
	fi

restart-docker: /usr/bin/docker
	sudo systemctl restart docker
	sudo chmod 777 /var/run/docker.sock

PATH:=$(GOPATH)/bin:$(PATH)
HADOLINT=$(shell PATH=$(GOPATH):$(PATH) which hadolint)

lint-dockerfile:
ifeq (,$(shell PATH=$(GOPATH):$(PATH) which hadolint))
	mkdir -p $(GOPATH)/bin
	curl -o $(GOPATH)/bin/hadolint -sNSL https://github.com/hadolint/hadolint/releases/download/v1.17.1/hadolint-$(shell uname -s)-$(shell uname -m)
	chmod 755 $(GOPATH)/bin/hadolint
endif
	@echo "Running Dockerfile lint check ..."
	@hadolint $$(find .  -type f -not -path "./src/vendor/*"  -name "Dockerfile*")
	@echo "Dockerfile lint check OK"

lint-style:
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

lint-sanity: protos
	@echo "Running sanity check..."
	@cd src; \
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go vet -mod=vendor ./...
	@echo "Sanity check OK"

lint-mod:
	@echo "Running dependency check..."
	@cd src; \
	GOROOT=${GO_DIR} GOPATH=$(HOME)/app ${GO_BIN_PATH}/go mod verify
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
