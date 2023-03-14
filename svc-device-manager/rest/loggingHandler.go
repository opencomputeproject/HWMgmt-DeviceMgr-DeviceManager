package rest

import (
	"devicemanager/rest/redfish"
	"devicemanager/utils"
	"fmt"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"github.com/sirupsen/logrus"
)

type loggingHandler struct {
}

func (l *loggingHandler) handle(ctx iris.Context) {
	// Enable reading the request body multiple times.
	ctx.RecordRequestBody(true)

	var reqInfo redfish.RequestInformation

	// Retrieve request information from a request.
	err := ctx.ReadJSON(&reqInfo)
	if err != nil {
		missingInfoError := "Unable to retrieve information from a request: " + err.Error()
		logrus.Warn(missingInfoError)

		ctx.Next()
	}

	requestUri := utils.UriConverter.DmToRedfish(fmt.Sprintf("https://%s%s", reqInfo.Host, ctx.Request().RequestURI))
	logrus.Debugf("request: %s on %s", ctx.Request().Method, requestUri)
	ctx.Next()
}

func newLoggingHandler() context.Handler {
	return new(loggingHandler).handle
}
