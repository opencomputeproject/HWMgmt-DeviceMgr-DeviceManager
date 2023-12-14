package rest

import (
	"devicemanager/config"
	odimConfig "github.com/ODIM-Project/ODIM/lib-utilities/config"
	"github.com/kataras/iris/v12"
	"github.com/sirupsen/logrus"
	"net/http"
)

func InitializeAndRunApplication(config config.Config) {
	app := iris.New()

	app.UseRouter(newLoggingHandler())

	app.WrapRouter(trailingSlashRouter)
	createRouting(app, config)

	server, err := newHttpServer(config)
	if err != nil {
		logrus.Fatal("error during initialization of Device Manager server: " + err.Error())
	}

	app.Run(iris.Server(server))
}

func createRouting(app *iris.Application, config config.Config) {
	basicAuthHandler := newBasicAuthHandler(config.UserName, config.Password)
	getGenericResourceHandler := newGenericResourceHandler(config)

	routes := app.Party("/ODIM/v1")
	{
		chassis := routes.Party("/Chassis", basicAuthHandler)
		chassis.Get("", getGenericResourceHandler)
		chassis.Get("/{id}", getGenericResourceHandler)
		chassis.Get("/{id}/Thermal", getGenericResourceHandler)
		chassis.Get("/{id}/Assembly", getGenericResourceHandler)
		chassis.Get("/{id}/Drives", getGenericResourceHandler)
		chassis.Get("/{id}/Memory", getGenericResourceHandler)
		chassis.Get("/{id}/MemoryDomains", getGenericResourceHandler)
		chassis.Get("/{id}/Sensors", getGenericResourceHandler)
		chassis.Get("/{id}/LogServices", getGenericResourceHandler)
		chassisPower := chassis.Party("/{id}/Power")
		chassisPower.Get("", getGenericResourceHandler)
		chassisNetworkAdapters := chassis.Party("/{id}/NetworkAdapters")
		chassisNetworkAdapters.Get("", getGenericResourceHandler)
		chassisNetworkAdapters.Get("/{id}", getGenericResourceHandler)
		chassisNetworkAdapters.Get("/{id}/Assembly", getGenericResourceHandler)
		chassisNetworkAdapters.Get("/{id}/NetworkDeviceFunctions", getGenericResourceHandler)
		chassisNetworkAdapters.Get("/{id}/NetworkDeviceFunctions/{id2}", getGenericResourceHandler)
		chassisNetworkAdapters.Get("/{id}/NetworkDeviceFunctions/{id2}/VLANS", getGenericResourceHandler)
		chassisNetworkAdapters.Get("/{id}/NetworkPorts", getGenericResourceHandler)
		chassisNetworkAdapters.Get("/{id}/NetworkPorts/{id2}", getGenericResourceHandler)
		chassisNetworkAdapters.Get("/{id}/Ports", getGenericResourceHandler)
		systems := routes.Party("/Systems", basicAuthHandler)
		systems.Get("", getGenericResourceHandler)
		systems.Get("/{id}", getGenericResourceHandler)
		systems.Get("/{id}/BootOptions", getGenericResourceHandler)
		systems.Get("/{id}/BootOptions/{id2}", getGenericResourceHandler)
		systems.Get("/{id}/Processors", getGenericResourceHandler)
		systems.Get("/{id}/Processors/{id2}", getGenericResourceHandler)
		systems.Get("/{id}/Memory", getGenericResourceHandler)
		systems.Get("/{id}/Memory/{id2}", getGenericResourceHandler)
		systems.Get("/{id}/NetworkInterfaces", getGenericResourceHandler)
		systems.Get("/{id}/NetworkInterfaces/{id2}", getGenericResourceHandler)
		systems.Get("/{id}/MemoryDomains", getGenericResourceHandler)
		systems.Get("/{id}/SecureBoot", getGenericResourceHandler)
		systems.Get("/{id}/PCIeDevices/{id2}", getGenericResourceHandler)
		systems.Get("/{id}/Bios", getGenericResourceHandler)
		systems.Get("/{id}/Bios/Settings", getGenericResourceHandler)
		systems.Post("/{id}/Actions/ComputerSystem.Reset", newResetComputerSystemHandler(config))

		ethernetInterfaces := systems.Party("/{id}/EthernetInterfaces")
		ethernetInterfaces.Get("", getGenericResourceHandler)
		ethernetInterfaces.Get("/{id}", getGenericResourceHandler)
		ethernetInterfaces.Get("/{id}/VLANS", getGenericResourceHandler)
		ethernetInterfaces.Get("/{id}/VLANS/{id2}", getGenericResourceHandler)

		logService := systems.Party("/{id}/LogServices")
		logService.Get("", getGenericResourceHandler)
		logService.Get("/{id}", getGenericResourceHandler)
		logService.Get("/{id}/Entries", getGenericResourceHandler)
		logService.Get("/{id}/Entries/{id2}", getGenericResourceHandler)

		storage := routes.Party("/{id}/Storage")
		storage.Get("", getGenericResourceHandler)
		storage.Get("/{id}", getGenericResourceHandler)
		storage.Get("/{id}/Volumes", getGenericResourceHandler)
		storage.Get("/{id}/Volumes/{id2}", getGenericResourceHandler)
		storage.Get("/{id}/Drives/{id2}", getGenericResourceHandler)

		storagePools := storage.Party("/{id}/StoragePools")
		storagePools.Get("", getGenericResourceHandler)
		storagePools.Get("/{id}", getGenericResourceHandler)
		storagePools.Get("/{id}/AllocatedVolumes", getGenericResourceHandler)
		storagePools.Get("/{id}/AllocatedVolumes/{id2}", getGenericResourceHandler)

		capacitySources := storagePools.Party("/{id}/CapacitySources")
		capacitySources.Get("/{id}/ProvidingVolumes", getGenericResourceHandler)
		capacitySources.Get("/{id}/ProvidingVolumes/{id2}", getGenericResourceHandler)
		capacitySources.Get("/{id}/ProvidingDrives", getGenericResourceHandler)

		update := routes.Party("/UpdateService", basicAuthHandler)
		update.Post("/Actions/UpdateService.SimpleUpdate", newPostSimpleUpdateHandler(config))

		managers := routes.Party("/Managers", basicAuthHandler)
		managers.Get("", newManagersCollectionHandler(config))
		managers.Get("/{id}", newManagerHandler(config))
	}

	routes.Get("/Status", newStatusHandler(config))
	routes.Post("/Startup", basicAuthHandler, newStartupHandler())
	routes.Post("/validate", basicAuthHandler, newValidateHandler(config))
}

func newHttpServer(c config.Config) (*http.Server, error) {
	serverConfig := &odimConfig.HTTPConfig{
		Certificate:   &c.PKICertificate,
		PrivateKey:    &c.PKIPrivateKey,
		CACertificate: &c.PKIRootCA,
		ServerAddress: c.Host,
		ServerPort:    c.Port,
	}

	return serverConfig.GetHTTPServerObj()
}

func trailingSlashRouter(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	path := r.URL.Path
	if len(path) > 1 && path[len(path)-1] == '/' && path[len(path)-2] != '/' {
		path = path[:len(path)-1]
		r.RequestURI = path
		r.URL.Path = path
	}
	next(w, r)
}
