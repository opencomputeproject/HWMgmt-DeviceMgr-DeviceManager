package rest

import (
	"devicemanager/config"
	"github.com/kataras/iris/v12"
)

var configForTesting = config.Config{
	RootServiceUUID: "99999999-9999-9999-9999-999999999999",
	UserName: "admin",
	Password: "YmzjkpHW8NIKoLJ6Lp5bufhl6bosH8U7Gy7rLeo8t8ixFk5soWalYa4FX8m8cjnfI6AKtoxTo7DfGdphNk3Y8g==",
	FirmwareVersion: "v1.0.0",
}

func testApp() *iris.Application {
	app := iris.New()
	app.WrapRouter(trailingSlashRouter)
	createRouting(app, configForTesting)
	return app
}
