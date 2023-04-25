package rest

import (
	"github.com/kataras/iris/v12/httptest"
	"net/http"
	"testing"
)

func Test_get_manager(t *testing.T) {
	app := testApp()
	request := httptest.New(t, app).Request(http.MethodGet, "/ODIM/v1/Managers/"+testConfig.RootServiceUUID)
	request.
		WithBasicAuth("admin", "D3v1ceMgr").
		Expect().
		Status(http.StatusOK).
		JSON().Object().
		ContainsKey("Name").
		ValueEqual("FirmwareVersion", testConfig.FirmwareVersion).
		ValueEqual("UUID", testConfig.RootServiceUUID).
		ValueEqual("Id", testConfig.RootServiceUUID).
		ContainsKey("ManagerType").
		ContainsKey("Certificates").
		Value("Status").Object().
		ContainsKey("State")
}
