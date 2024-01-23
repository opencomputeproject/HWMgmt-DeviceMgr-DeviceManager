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

type patchPowerHandler struct {
	cfg config.Config
}

func (r *patchPowerHandler) handle(ctx iris.Context) {
	if ctx.GetHeader("Authorization") == "" {
		noValidAuthError := "No valid authorization"
		ctx.StatusCode(http.StatusUnauthorized)
		logrus.Error(noValidAuthError)
		ctx.WriteString(noValidAuthError)
		return
	}

	var reqInfo redfish.RequestInformation

	// Get information from the request.
	err := ctx.ReadJSON(&reqInfo)
	if err != nil {
		missingInfoError := "Unable to retrieve information from a request: " + err.Error()
		logrus.Error(missingInfoError)
		ctx.StatusCode(http.StatusBadRequest)
		ctx.WriteString(missingInfoError)
		return
	}

	httpClient := redfish.NewHttpClient(r.cfg).WithBasicAuth(reqInfo.Username, string(reqInfo.Password))
	uri := fmt.Sprintf("https://%s%s", reqInfo.Host, ctx.Request().RequestURI)

	response, err := httpClient.Patch(uri, reqInfo.Body)
	if err != nil {
		errorMessage := fmt.Sprintf("PATCH action failed on %s due to: %s", uri, err.Error())
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

	ctx.StatusCode(response.StatusCode)
	ctx.Write(body)
}

func newPatchPowerHandler(cfg config.Config) context.Handler {
	return (&patchPowerHandler{
		cfg: cfg,
	}).handle
}
