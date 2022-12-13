package rest

import (
	"devicemanager/config"
	"devicemanager/rest/redfish"
	"fmt"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
)

type genericResourceHandler struct {
	cfg config.Config
}

func (g *genericResourceHandler) handle(ctx iris.Context) {
	var reqInfo redfish.RequestInformation

	// Retrieve request information from a request.
	err := ctx.ReadJSON(&reqInfo)
	if err != nil {
		errorMessage := "Unable to retrieve mandatory information from a request: " + err.Error()
		logrus.Error(errorMessage)
		ctx.StatusCode(http.StatusBadRequest)
		ctx.WriteString(errorMessage)
		return
	}

	httpClient := redfish.NewHttpClient(g.cfg).WithBasicAuth(reqInfo.Username, string(reqInfo.Password))

	requestedUri := fmt.Sprintf("https://%s%s", reqInfo.Host, ctx.Request().RequestURI)

	response, err := httpClient.Get(requestedUri)
	if err != nil {
		errorMessage := "GET action failed due to: " + err.Error()
		logrus.Error(errorMessage)
		if response == nil {
			ctx.StatusCode(http.StatusInternalServerError)
			ctx.WriteString(errorMessage)
			return
		}
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		errorMessage := "Error while reading response body: " + err.Error()
		logrus.Error(errorMessage)
		ctx.StatusCode(http.StatusInternalServerError)
		ctx.WriteString(errorMessage)
		return
	}

	if response.StatusCode == http.StatusUnauthorized {
		ctx.StatusCode(http.StatusUnauthorized)
		ctx.WriteString("Authentication failed. Wrong username and/or password")
		return
	}
	if response.StatusCode >= 300 {
		logrus.Errorf("GET action for %s ended with %d status code.", requestedUri, response.StatusCode)
	}

	ctx.StatusCode(response.StatusCode)
	ctx.Write(body)
}

func newGenericResourceHandler(cfg config.Config) context.Handler {
	return (&genericResourceHandler{
		cfg: cfg,
	}).handle
}
