package rest

import (
	"devicemanager/config"
	"github.com/kataras/iris/v12"
)

var configForTesting = config.Config{
	UserName: "admin",
	Password: "WjivsaGNQI5s02f525Hiq5vOg0za09okGDzBdJVsIM413TnCvTaq6QcRGuPWraNT92l6XxqPxWeq6eTKQanRnQ==",
}

func testApp() *iris.Application {
	app := iris.New()
	app.WrapRouter(trailingSlashRouter)
	createRouting(app, configForTesting)
	return app
}
