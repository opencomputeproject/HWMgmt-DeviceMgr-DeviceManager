package rest

import (
	"devicemanager/config"
	"devicemanager/rest/redfish"
	"encoding/json"
	"fmt"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
)

type postSimpleUpdateHandler struct {
	cfg config.Config
}

func (r *postSimpleUpdateHandler) handle(ctx iris.Context) {
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

	// Validate Simple Update request
	err = validateSimpleUpdateAction(reqInfo.Body)
	if err != nil {
		simpleUpdateRequestError := fmt.Sprintf("invalid simple update request: %s", err.Error())
		logrus.Error(simpleUpdateRequestError)
		ctx.StatusCode(http.StatusBadRequest)
		ctx.WriteString(simpleUpdateRequestError)
		return
	}

	httpClient := redfish.NewHttpClient(r.cfg).WithBasicAuth(reqInfo.Username, string(reqInfo.Password))
	uri := fmt.Sprintf("https://%s%s", reqInfo.Host, ctx.Request().RequestURI)

	response, err := httpClient.Post(uri, reqInfo.Body)
	if err != nil {
		errorMessage := fmt.Sprintf("POST action failed on %s due to: %s", uri, err.Error())
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

func newPostSimpleUpdateHandler(cfg config.Config) context.Handler {
	return (&postSimpleUpdateHandler{
		cfg: cfg,
	}).handle
}

func validateSimpleUpdateAction(request []byte) error {
	var simpleUpdateRequest SimpleUpdateAction
	err := json.Unmarshal(request, &simpleUpdateRequest)
	if err != nil {
		return fmt.Errorf("unmarshalling failed for simple update action, err: %s", err.Error())
	}

	if len(simpleUpdateRequest.ImageURI) == 0 {
		return fmt.Errorf("required value ImageURI is missing")
	}

	return nil
}

type SimpleUpdateAction struct {
	ImageURI string `json:"ImageURI"`
}
