package rest

import (
	"github.com/kataras/iris/v12/httptest"
	"net/http"
	"testing"
)

func Test_get_status(t *testing.T) {
	app := testApp()
	request := httptest.New(t, app).Request(http.MethodGet, "/ODIM/v1/Status")
	request.
		Expect().
		Status(http.StatusOK).
		JSON().Object().
		ContainsKey("Name").
		ContainsKey("Version").
		ContainsKey("Status").
		Value("Status").Object().
		ContainsKey("Available").
		ContainsKey("Uptime").
		ContainsKey("TimeStamp")
}
