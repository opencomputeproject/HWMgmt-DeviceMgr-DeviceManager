package rest

import (
	"devicemanager/config"
	"github.com/kataras/iris/v12"
)

var configForTesting = config.Config{
	UserName: "admin",
	Password: "YmzjkpHW8NIKoLJ6Lp5bufhl6bosH8U7Gy7rLeo8t8ixFk5soWalYa4FX8m8cjnfI6AKtoxTo7DfGdphNk3Y8g==",
}

func testApp() *iris.Application {
	app := iris.New()
	app.WrapRouter(trailingSlashRouter)
	createRouting(app, configForTesting)
	return app
}
