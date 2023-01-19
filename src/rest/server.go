package rest

import (
	"devicemanager/config"
	odimConfig "github.com/ODIM-Project/ODIM/lib-utilities/config"
	"github.com/kataras/iris/v12"
	"github.com/sirupsen/logrus"
	"net/http"
)

func InitializeAndRunApplication(config *config.Config) {
	app := iris.New()
	app.WrapRouter(trailingSlashRouter)
	createRouting(app, config)

	server, err := newHttpServer(config)
	if err != nil {
		logrus.Fatal("error during initialization of Device Manager server: " + err.Error())
	}

	app.Run(iris.Server(server))
}

func createRouting(app *iris.Application, config *config.Config) {
	basicAuthHandler := newBasicAuthHandler(config.UserName, config.Password)
	routes := app.Party("/ODIM/v1")
	{
		systems := routes.Party("/Systems", basicAuthHandler)
		systems.Get("")
	}

	routes.Get("/Status", newStatusHandler(config))
	routes.Post("/Startup", basicAuthHandler, newStartupHandler())
}

func newHttpServer(c *config.Config) (*http.Server, error) {
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
