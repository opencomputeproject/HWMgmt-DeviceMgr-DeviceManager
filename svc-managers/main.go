//(C) Copyright [2020] Hewlett Packard Enterprise Development LP
//
//Licensed under the Apache License, Version 2.0 (the "License"); you may
//not use this file except in compliance with the License. You may obtain
//a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//License for the specific language governing permissions and limitations
// under the License.
package main

import (
	"encoding/json"
	"os"

	"github.com/sirupsen/logrus"

	"fmt"
	"time"
	dmtf "github.com/ODIM-Project/ODIM/lib-dmtf/model"
	"github.com/ODIM-Project/ODIM/lib-utilities/common"
	"github.com/ODIM-Project/ODIM/lib-utilities/config"
	managersproto "github.com/ODIM-Project/ODIM/lib-utilities/proto/managers"
	"github.com/ODIM-Project/ODIM/lib-utilities/services"
	"github.com/ODIM-Project/ODIM/svc-managers/managers"
	"github.com/ODIM-Project/ODIM/svc-managers/mgrcommon"
	"github.com/ODIM-Project/ODIM/svc-managers/mgrmodel"
	"github.com/ODIM-Project/ODIM/svc-managers/rpc"
)

var log = logrus.New()

func main() {

	// verifying the uid of the user
	if uid := os.Geteuid(); uid == 0 {
		log.Fatal("Manager Service should not be run as the root user")
	}

	if err := config.SetConfiguration(); err != nil {
		log.Fatal("fatal: error while trying set up configuration: %v" + err.Error())
	}

	config.CollectCLArgs()

	if err := common.CheckDBConnection(); err != nil {
		log.Fatal(err.Error())
	}

	var managerInterface = mgrcommon.DBInterface{
		AddManagertoDBInterface: mgrmodel.AddManagertoDB,
		GenericSave:             mgrmodel.GenericSave,
	}
	err := addManagertoDB(managerInterface)
	if err != nil {
		log.Fatal(err.Error())
	}
	configFilePath := os.Getenv("CONFIG_FILE_PATH")
	if configFilePath == "" {
		log.Fatal("error: no value get the environment variable CONFIG_FILE_PATH")
	}
	go mgrcommon.TrackConfigFileChanges(configFilePath, managerInterface)

	err = services.InitializeService(services.Managers)
	if err != nil {
		log.Fatal("fatal: error while trying to initialize service: %v" + err.Error())
	}
	mgrcommon.Token.Tokens = make(map[string]string)
	registerHandlers()
	if err = services.ODIMService.Run(); err != nil {
		log.Fatal("failed to run a service: " + err.Error())
	}
}

func registerHandlers() {
	manager := new(rpc.Managers)

	manager.IsAuthorizedRPC = services.IsAuthorized
	manager.EI = managers.GetExternalInterface()

	managersproto.RegisterManagersServer(services.ODIMService.Server(), manager)
}

func addManagertoDB(managerInterface mgrcommon.DBInterface) error {
	mgr := mgrmodel.RAManager{
		Name:            "odimra",
		ManagerType:     "Service",
		FirmwareVersion: config.Data.FirmwareVersion,
		ID:              config.Data.RootServiceUUID,
		UUID:            config.Data.RootServiceUUID,
		State:           "Enabled",
		Health:          "OK",
		HealthRollup:	 "OK",
		Description:     "Odimra Manager",
		LogServices: &dmtf.Link{
			Oid: "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/LogServices",
		},
		EthernetInterfaces:  	 &dmtf.Link{
			Oid: "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/EthernetInterfaces",
		},
		NetworkProtocol: 		&dmtf.Link{
			Oid: "/redfish/v1/Managers/" +  config.Data.RootServiceUUID + "/NetworkProtocol",
		},
		Model:      "ODIMRA" + " " + config.Data.FirmwareVersion,
		PowerState: "On",
		ServiceEntryPointUUID: config.Data.RootServiceUUID, 
	}
	managerInterface.AddManagertoDBInterface(mgr)

	//adding LogeSrvice Collection
	data := dmtf.Collection{
		ODataContext: "/redfish/v1/$metadata#LogServiceCollection.LogServiceCollection",
		ODataID:      "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/LogServices",
		ODataType:    "#LogServiceCollection.LogServiceCollection",
		Description:  "Logs view",
		Members: []*dmtf.Link{
			&dmtf.Link{
				Oid: "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/LogServices/SL",
			},
		},
		MembersCount: 1,
		Name:         "Logs",
	}
	dbdata, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("unable to marshal manager data: %v", err)
	}
	key := "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/LogServices"
	mgrmodel.GenericSave([]byte(dbdata), "LogServicesCollection", key)

	//adding LogService Members
	logEntrydata := dmtf.LogServices{
		Ocontext:    "/redfish/v1/$metadata#LogServiceCollection.LogServiceCollection",
		Oid:         "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/LogServices/SL",
		Otype:       "#LogService.v1_3_0.LogService",
		Description: "Logs view",
		Entries: &dmtf.Entries{},
		ID:              "SL",
		Name:            "Security Log",
		OverWritePolicy: "WrapsWhenFull",
		DateTime: 		 time.Now().Format(time.RFC3339),
		DateTimeLocalOffset: "+00:00",
		ServiceEnabled:		true,
		Status:          &dmtf.Status{State: "Enabled", Health: "OK", HealthRollup: "OK"},
	}
	dbdata, err = json.Marshal(logEntrydata)
	if err != nil {
		return fmt.Errorf("unable to marshal manager data: %v", err)
	}
	key = "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/LogServices/SL"
	mgrmodel.GenericSave([]byte(dbdata), "LogServices", key)
	
	//adding empty EthernetInterfaces Collection
	ethernetInterfaces := dmtf.Collection{
		ODataContext: "/redfish/v1/$metadata#EthernetInterfacesCollection.EthernetInterfacesCollection",
		ODataID:      "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/EthernetInterfaces",
		ODataType:    "#EthernetInterfacesCollection.EthernetInterfacesCollection",
		Description:  "EthernetInterfaces collection view",
		Members: 	[]*dmtf.Link{},
		MembersCount: 1,
		Name:         "EthernetInterfaces",
	}
	dbdata, err = json.Marshal(ethernetInterfaces)
	if err != nil {
		return fmt.Errorf("unable to marshal manager data: %v", err)
	}
	key = "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/EthernetInterfaces"
	mgrmodel.GenericSave([]byte(dbdata), "EthernetInterfacesCollection", key)

	//adding NetworkProtocol
	networkProtocol := dmtf.NetworkProtocol{
		ODataID:      "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/NetworkProtocol",
		ODataType:    "#ManagerNetworkProtocol.ManagerNetworkProtocol",
		Description:  "NetworkProtocol",
		ID:			  "NetworkProtocol",
		Name:         "NetworkProtocol",
	}
	dbdata, err = json.Marshal(networkProtocol)
	if err != nil {
		log.Error()
	}
	key = "/redfish/v1/Managers/" + config.Data.RootServiceUUID + "/NetworkProtocol"
	mgrmodel.GenericSave([]byte(dbdata), "NetworkProtocol", key)
	return nil
}
