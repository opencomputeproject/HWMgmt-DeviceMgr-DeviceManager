package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sirupsen/logrus"
)

const SimpleUpdateURI = "/redfish/v1/UpdateService/Actions/SimpleUpdate"

type UpdateService struct {
	Server *Server
}

type SimpleUpdateRequest struct {
	ImageURI         string   `json:"ImageURI"`
	TransferProtocol string   `json:"TransferProtocol,omitempty"`
	Targets          []string `json:"Targets,omitempty"`
	Username         string   `json:"Username,omitempty"`
	Password         string   `json:"Password,omitempty"`
}

// SimpleUpdate sends Redfish SimpleUpdate request to given device.
func (u *UpdateService) SimpleUpdate(ipAddress, authToken string, request SimpleUpdateRequest) (string, error) {
	userData := u.Server.getUserAuthData(ipAddress, authToken)
	if (userData == userAuth{}) {
		authNotFoundError := errors.New(ErrUserAuthNotFound.String())
		logrus.Errorf(authNotFoundError.Error())
		return "", authNotFoundError
	}

	err := validateSimpleUpdateRequest(request)
	if err != nil {
		logrus.Errorf("validateSimpleUpdateRequest returned error: %s", err.Error())
		return "", err
	}

	response, body, statusCode, postErr := postHTTPDataByRfAPI(ipAddress, SimpleUpdateURI, userData, request)
	if postErr != nil {
		logrus.Errorf("error during http post to redfish device: %s", postErr.Error())
		return "", err
	}

	// Redfish SimpleUpdate should return 202 Accepted status code. In addition, Task Monitor should be present in Location header.
	if statusCode != http.StatusAccepted {
		logrus.Errorf("simpleUpdate status code is different from 202 Accepted. Actual status code: %v,response body: %s", statusCode, body)
	}

	taskURI, locErr := response.Location()
	if locErr != nil {
		logrus.Errorf("location header is empty. Error: %s", locErr.Error())
		return "", locErr
	}

	return taskURI.String(), nil
}

func (s *SimpleUpdateRequest) ToJson() string {
	request, err := json.Marshal(s)
	if err != nil {
		logrus.Errorf("json.Marshal returned error: %s", err.Error())
		return ""
	}

	return string(request)
}

func validateSimpleUpdateRequest(request SimpleUpdateRequest) error {
	if len(request.ImageURI) == 0 {
		return errors.New("image URI is required for SimpleUpdate")
	}

	return nil
}
