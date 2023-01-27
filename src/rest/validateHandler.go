package rest

import (
	"devicemanager/config"
	"devicemanager/rest/redfish"
	"encoding/json"
	"fmt"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"github.com/sirupsen/logrus"
	"net/http"
)

type validateHandler struct {
	cfg config.Config
}

func (v *validateHandler) handle(ctx iris.Context) {
	if ctx.GetHeader("Authorization") == "" {
		noValidAuthError := "No valid authorization"
		ctx.StatusCode(http.StatusUnauthorized)
		logrus.Error(noValidAuthError)
		ctx.WriteString(noValidAuthError)
		return
	}

	var reqInfo redfish.RequestInformation

	// Retrieve request information from a request.
	err := ctx.ReadJSON(&reqInfo)
	if err != nil {
		missingInfoError := "Unable to retrieve mandatory information from a request: " + err.Error()
		logrus.Error(missingInfoError)
		ctx.StatusCode(http.StatusBadRequest)
		ctx.WriteString(missingInfoError)
		return
	}

	httpClient := redfish.NewHttpClient(v.cfg).WithBasicAuth(reqInfo.Username, string(reqInfo.Password))
	serviceRootUri := fmt.Sprintf("https://%s%s", reqInfo.Host, "/redfish/v1")

	response, err := httpClient.Get(serviceRootUri)
	if err != nil {
		errorMessage := "GET action failed due to: " + err.Error()
		logrus.Error(errorMessage)
		if response == nil {
			ctx.StatusCode(http.StatusInternalServerError)
			ctx.WriteString(errorMessage)
			return
		}
	}

	systemsUri := fmt.Sprintf("https://%s%s", reqInfo.Host, "/redfish/v1/Systems")

	resp, err := httpClient.Get(systemsUri)
	if err != nil {
		errorMessage := "GET action failed due to: " + err.Error()
		logrus.Error(errorMessage)
		if response == nil {
			ctx.StatusCode(http.StatusInternalServerError)
			ctx.WriteString(errorMessage)
			return
		}
	}

	defer resp.Body.Close()
	serviceRoot := &ServiceRoot{}
	err = json.NewDecoder(resp.Body).Decode(serviceRoot)
	if err != nil {
		errorMessage := "Error while reading response body: " + err.Error()
		logrus.Error(errorMessage)
		ctx.StatusCode(http.StatusInternalServerError)
		ctx.WriteString(errorMessage)
		return
	}

	if resp.StatusCode == http.StatusUnauthorized {
		ctx.StatusCode(http.StatusUnauthorized)
		ctx.WriteString("Authentication failed. Wrong username and/or password")
		return
	}

	if resp.StatusCode >= 300 {
		logrus.Errorf("GET action for %s ended with %d status code.", systemsUri, resp.StatusCode)
	}

	ctx.StatusCode(resp.StatusCode)
	ctx.JSON(&RedfishEntity{
		Host:            reqInfo.Host,
		Username:        reqInfo.Username,
		ServiceRootUuid: serviceRoot.UUID,
	})
}

func newValidateHandler(cfg config.Config) context.Handler {
	return (&validateHandler{
		cfg: cfg,
	}).handle
}

type RedfishEntity struct {
	Host            string `json:"ServerIP"`
	Username        string `json:"Username"`
	ServiceRootUuid string `json:"device_UUID"`
}

type ServiceRoot struct {
	UUID string `json:"UUID"`
}
