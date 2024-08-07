package rest

import (
	"devicemanager/config"
	"github.com/ODIM-Project/ODIM/lib-dmtf/model"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"net/http"
	"time"
)

type managerHandler struct {
	dmManager model.Manager
}

func (m *managerHandler) handle(ctx iris.Context) {
	managerUri := ctx.Request().RequestURI
	if managerUri == m.dmManager.ODataID {
		ctx.StatusCode(http.StatusOK)
		ctx.JSON(m.dmManager)
		return
	}

	ctx.StatusCode(http.StatusNotFound)
}

func newManagerHandler(cfg config.Config) context.Handler {
	return (&managerHandler{
		dmManager: createDmManager(cfg),
	}).handle
}

func createDmManager(cfg config.Config) model.Manager {
	return model.Manager{
		ODataContext:    "/ODIM/v1/$metadata#Manager.Manager",
		ODataID:         "/ODIM/v1/Managers/" + cfg.RootServiceUUID,
		ODataType:       "#Manager.v1_13_0.Manager",
		Name:            deviceManagerName,
		ManagerType:     "RackManager",
		ID:              cfg.RootServiceUUID,
		UUID:            cfg.RootServiceUUID,
		FirmwareVersion: cfg.FirmwareVersion,
		Status:          &model.Status{State: "Enabled", Health: "OK", HealthRollup: "OK"},
		DateTime:        time.Now().Format(time.RFC3339),
		DateTimeLocalOffset: "+00:00",
		Description:	"Device Manager",
		Model:			"Device Manager",
		ServiceEntryPointUUID: cfg.RootServiceUUID,
		PowerState: 	"On",
		SerialConsole:	model.SerialConsole{},
		EthernetInterfaces:  	&model.Link{
			Oid: "/redfish/v1/Managers/" + cfg.RootServiceUUID + "/EthernetInterfaces",
		},
		NetworkProtocol: 		&model.Link{
			Oid: "/redfish/v1/Managers/" + cfg.RootServiceUUID + "/NetworkProtocol",
		},
		LogServices:	&model.Link{
			Oid: "/redfish/v1/Managers/" + cfg.RootServiceUUID + "/LogServices",
		},
		Links:	&model.ManagerLinks{
			ManagerForChassis:  []model.Link{},
			ManagerForServers:  []model.Link{},
			ManagerForManagers: []model.Link{},
			ManagerInChassis: 	&model.Link{},
		},
	}
}
