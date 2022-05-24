# Setting up of dev env and building the ODIM services

## Pre-requisites
<p>ODIM builds and runs on a Ubuntu LTS 20.04 server OS on a x86_64 platform. Building or running on a different OS and or platform will require changes that will not be covered here.</p>

## The following software is required to build the services
- golang v1.17.2

## The following third party softwares are required to run the services
- Kafka 2.5.0
- Redis v6.2.5
- ZooKeeper v3.5.8
<p>These have been included as per ODIM design and implementation. Changes to these will need code updates as well.</p>

## setting up build pre-requisites
### on the server install the build requirements
```
$ sudo apt-get update
$ sudo apt-get -y install git unzip build-essential autoconf libtool
```
### install latest version of protobuf
This is required only if a new version protobuf is not installed on the system.
```
$ cd /tmp
$ git clone https://github.com/google/protobuf.git
$ cd protobuf 
$ ./autogen.sh 
$ ./configure 
# good practise to run make && make test make install is mandatory
$ sudo make install 
$ sudo ldconfig 
$ make clean 
$ cd .. 
$ rm -r protobuf
```
### Install protoc-gen-go-grpc
```
$ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```
### Install protoc-gen-go@v1.3.2
We have encountered compile issues with some versions of the gen go compiler. It is recommended that you use the version specified.
```
$ go install github.com/golang/protobuf/protoc-gen-go@v1.3.2
```
## Building services
navigate to the base directory:
```
$ cd <Path to HWMgmt-DeviceMgr-DeviceManager>
```
The following source directories have been added from ODIM sources to the device manager sources svc-account-session, svc-aggregation, svc-api, svc-events, svc-task, svc-systems. The following library directories have been added from ODIM sources to the device manager sources - these are needed to build any ODIM service namely lib-dmtf  lib-messagebus  lib-persistence-manager lib-utilities.
lib-rest-client used to make redfish calls to plugins is also moved from ODIM is needed to build svc-systems, svc-aggregation.

### first build the proto files(in the base directory itself)
```
protos=("account" "aggregator" "auth" "chassis" "events" "fabrics" "managers" "role" "session" "systems" "task" "telemetry" "update" "compositionservice")
for str in ${protos[@]}; do
  proto_path="$(pwd)/lib-utilities/proto/$str"
  proto_file_name="$str.proto"
  if [ $str == 'auth' ]
  then
    proto_file_name="odim_auth.proto"
  fi
  protoc --go_opt=M$proto_file_name=./ --go_out=plugins=grpc:$proto_path --proto_path=$proto_path $proto_file_name
done
```
## then build services
```
svcs=("svc-account-session" "svc-aggregation" "svc-api" "svc-events" "svc-task" "svc-systems")
for svc in ${svcs[@]}; do
  cd "$svc"
  go build
  cd ..
done
```
## Further Information
<p>ODIM library code and select services are moved here to be used with device manager project. As the issue https://github.com/opencomputeproject/HWMgmt-DeviceMgr-DeviceManager/issues/2 was prescriptive on the service to be moved we have stuck to the agenda.So while this code is building, this will require modifications to integrate and run with device manager. This in turn will depend on the architecture decided by the device manager project.</p>
<p>The ODIM build directory contents may be used for reference https://github.com/ODIM-Project/ODIM/tree/main/build. The device manager project may use its own build/packaging mechanism. ODIM needs CA signed certificates to run. Scripts to generate such certificates are provided at https://github.com/ODIM-Project/ODIM/tree/main/build/cert_generator. Installations having their own CA certificates/infrastructure need not use these scripts. The ODIM configuration file is available at https://github.com/ODIM-Project/ODIM/blob/main/lib-utilities/config/odimra_config.json and description of the same is available at https://github.com/ODIM-Project/ODIM/blob/main/lib-utilities/config/README.md</p>

