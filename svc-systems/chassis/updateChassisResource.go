package chassis

import (
	"encoding/json"
	"fmt"
	"github.com/ODIM-Project/ODIM/lib-utilities/common"
	chassisproto "github.com/ODIM-Project/ODIM/lib-utilities/proto/chassis"
	"github.com/ODIM-Project/ODIM/lib-utilities/response"
	"github.com/ODIM-Project/ODIM/svc-systems/scommon"
	"github.com/ODIM-Project/ODIM/svc-systems/smodel"
	"net/http"
	"strings"
)

func (p *PluginContact) UpdateChassisResource(req *chassisproto.UpdateChassisResourceRequest) response.RPC {
	var resp response.RPC

	urlData := strings.Split(req.URL, "/")
	var tableName string
	if req.URL == "" {
		resourceName := urlData[len(urlData)-1]
		tableName = common.ChassisResource[resourceName]
	} else {
		tableName = urlData[len(urlData)-2]
	}

	uuid := strings.SplitN(tableName, ".", 2)
	target, err := smodel.GetTarget(uuid[0])
	if err != nil {
		return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, err.Error(), []interface{}{"Chassis", uuid[0]}, nil)
	}
	decryptedPasswordByte, error := p.DecryptPassword(target.Password)
	if error != nil {
		errorMessage := "error while trying to decrypt device password: " + err.Error()
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage, []interface{}{"Chassis", urlData}, nil)
	}

	target.PostBody = req.RequestBody
	target.Password = decryptedPasswordByte

	plugin, err := smodel.GetPluginData(target.PluginID)
	if err != nil {
		errorMessage := "error while trying to get plugin data"
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage, nil, nil)
	}

	var contactRequest scommon.PluginContactRequest
	contactRequest.ContactClient = p.ContactClient
	contactRequest.Plugin = plugin
	contactRequest.HTTPMethodType = http.MethodPatch
	contactRequest.OID = fmt.Sprintf("/ODIM/v1/Chassis/%s/Power", uuid[1])
	contactRequest.BasicAuth = map[string]string{
		"UserName": plugin.Username,
		"Password": string(plugin.Password),
	}
	contactRequest.DeviceInfo = target

	body, _, getResponse, contactErr := scommon.ContactPlugin(contactRequest, "error while trying patch Chassis/Power")
	if contactErr != nil {
		return common.GeneralError(getResponse.StatusCode, getResponse.StatusMessage, contactErr.Error(), nil, nil)
	}

	var resource map[string]interface{}
	json.Unmarshal(body, &resource)
	resp.Body = resource
	resp.StatusCode = http.StatusOK
	resp.StatusMessage = response.Success
	return resp
}
