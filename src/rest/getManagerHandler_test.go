package rest

import (
	"github.com/kataras/iris/v12/httptest"
	"net/http"
	"testing"
)

func TestGetManager(t *testing.T) {
	app := testApp()
	request := httptest.New(t, app).Request(http.MethodGet, "/ODIM/v1/Managers/"+configForTesting.RootServiceUUID)
	request.
		WithBasicAuth("admin", "D3v1ceMgr").
		Expect().
		Status(http.StatusOK).
		JSON().Object().
		ContainsKey("Name").
		ValueEqual("FirmwareVersion", configForTesting.FirmwareVersion).
		ValueEqual("UUID", configForTesting.RootServiceUUID).
		ValueEqual("Id", configForTesting.RootServiceUUID).
		ContainsKey("ManagerType").
		ContainsKey("Certificates").
		Value("Status").Object().
		ContainsKey("State")
}
