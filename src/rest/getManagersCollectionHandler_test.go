package rest

import (
	"github.com/kataras/iris/v12/httptest"
	"net/http"
	"testing"
)

func TestGetManagersCollection(t *testing.T) {
	app := testApp()
	request := httptest.New(t, app).Request(http.MethodGet, "/ODIM/v1/Managers")
	request.
		WithBasicAuth("admin", "D3v1ceMgr").
		Expect().
		Status(http.StatusOK).
		JSON().Object().
		ContainsKey("Name").
		ContainsKey("Members").
		Value("Members").Array().Length().Equal(1)
}
