package rest

import (
	"github.com/kataras/iris/v12/httptest"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func Test_invalid_credentials(t *testing.T) {
	tests := []struct {
		username string
		password string
	}{
		{"dummyAdmin", "D3v1ceMgr"},
		{"admin", "dummyPassword"},
		{"", ""},
	}
	for _, test := range tests {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth(test.username, test.password)
		basicAuthHandler := newBasicAuthHandler(testConfig.UserName, testConfig.Password)

		httptest.Do(rec, req, basicAuthHandler)
		assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
	}
}

func Test_valid_credentials(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "D3v1ceMgr")
	basicAuthHandler := newBasicAuthHandler(testConfig.UserName, testConfig.Password)

	httptest.Do(rec, req, basicAuthHandler)
	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

func Test_missing_basic_auth_header(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	basicAuthHandler := newBasicAuthHandler(testConfig.UserName, testConfig.Password)

	httptest.Do(rec, req, basicAuthHandler)
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}
