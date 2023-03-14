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

type resetComputerSystemHandler struct {
	cfg config.Config
}

func (r *resetComputerSystemHandler) handle(ctx iris.Context) {
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

	err = validateResetSystemAction(reqInfo.Body)
	if err != nil {
		badResetTypeError := "bad reset system request: %s" + err.Error()
		logrus.Error(badResetTypeError)
		ctx.StatusCode(http.StatusBadRequest)
		ctx.WriteString(badResetTypeError)
		return
	}

	httpClient := redfish.NewHttpClient(r.cfg).WithBasicAuth(reqInfo.Username, string(reqInfo.Password))
	systemsUri := fmt.Sprintf("https://%s%s", reqInfo.Host, ctx.Request().RequestURI)

	response, err := httpClient.Post(systemsUri, reqInfo.Body)
	if err != nil {
		errorMessage := fmt.Sprintf("POST action failed on %s due to: %s", systemsUri, err.Error())
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

func newResetComputerSystemHandler(cfg config.Config) context.Handler {
	return (&resetComputerSystemHandler{
		cfg: cfg,
	}).handle
}

func validateResetSystemAction(request []byte) error {
	var resetSystemRequest ResetSystemAction
	err := json.Unmarshal(request, &resetSystemRequest)
	if err != nil {
		return fmt.Errorf("unmarshalling failed for reset system action, err: %s", err.Error())
	}

	if len(resetSystemRequest.ResetType) == 0 {
		return fmt.Errorf("missing ResetType value")
	}

	if !isAllowedResetValue(resetSystemRequest.ResetType) {
		return fmt.Errorf("%s is not allowed ResetType for ComputerSystem", resetSystemRequest.ResetType)
	}

	return nil
}

func isAllowedResetValue(value string) bool {
	allowedResetValues := []string{"ForceOff", "ForceOn", "ForceRestart", "GracefulRestart", "GracefulShutdown", "Nmi",
		"On", "Pause", "PowerCycle", "PushPowerButton", "Resume", "Suspend"}

	for _, resetSystemValue := range allowedResetValues {
		if resetSystemValue == value {
			return true
		}
	}

	return false
}

type ResetSystemAction struct {
	ResetType string `json:"ResetType"`
}
