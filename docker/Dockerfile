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

# docker build -t opencord/device-management:latest .
# docker build -t 10.90.0.101:30500/opencord/kafka-topic-exporter:latest .

FROM golang:1.12 AS build-env
SHELL ["/bin/bash", "-o",  "pipefail", "-c"]
RUN /bin/true | cat
ENV GO111MODULE=on
ENV PROTOC_VERSION="3.7.0"
ENV PROTOC_SHA256SUM="a1b8ed22d6dc53c5b8680a6f1760a305b33ef471bece482e92728f00ba2a2969"
ENV GRPC_GATEWAY_VERSION="1.16.0"
ENV GOPATH=$GOPATH
RUN apt-get update && apt-get install --no-install-recommends -y --allow-downgrades \
	git=1:2.20.1-2+deb10u1 \
	gcc=4:8.3.0-1 \
	curl=7.64.0-4 \
	unzip=6.0-23+deb10u1
RUN go get -v "github.com/golang/protobuf/protoc-gen-go@v1.3.2"
RUN go get -v "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway"
RUN mkdir /app
COPY src/* /app/
COPY . /app/
WORKDIR /app
RUN curl -L -o /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip 
RUN mkdir /tmp/protoc3
RUN   echo "$PROTOC_SHA256SUM  /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip" | sha256sum -c - \
 &&  unzip /tmp/protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /tmp/protoc3 \
 && mv /tmp/protoc3/bin/* /usr/local/bin/ \
 && mv /tmp/protoc3/include/* /usr/local/include/
RUN protoc --proto_path=proto -I"${GOPATH}/pkg/mod/github.com/grpc-ecosystem/grpc-gateway@v${GRPC_GATEWAY_VERSION}/third_party/googleapis" --go_out=plugins=grpc:.  proto/importer.proto
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o main .

FROM alpine:3.9.4
WORKDIR /app/
COPY device_key/https-server.crt .
COPY device_key/https-server.key .
COPY --from=build-env /app/main .
COPY --from=build-env /app/proto/importer.pb.go .
ENTRYPOINT ["./main"]
