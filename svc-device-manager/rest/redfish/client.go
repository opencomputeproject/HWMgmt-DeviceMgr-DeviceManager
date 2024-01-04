package redfish

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"devicemanager/config"
	"devicemanager/utils"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// HttpClient is responsible for communication with Redfish entity.
type HttpClient struct {
	client    *http.Client
	basicAuth *basicAuth
}

type basicAuth struct {
	username string
	password string
}

func NewHttpClient(cfg config.Config) *HttpClient {
	return &HttpClient{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: getHttpTransport(cfg),
		},
	}
}

func (h *HttpClient) WithBasicAuth(u string, p string) *HttpClient {
	if h.basicAuth == nil {
		h.basicAuth = &basicAuth{
			username: u,
			password: p,
		}
	} else {
		h.basicAuth.username = u
		h.basicAuth.password = p
	}

	return h
}

func getHttpTransport(cfg config.Config) *http.Transport {
	caCert, err := ioutil.ReadFile(cfg.PKIRootCAPath)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:   pool,
			ClientCAs: pool,
		},
	}
}

func (h *HttpClient) addDefaultHeaders(req *http.Request) *http.Request {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	if h.basicAuth != nil {
		basicAuthString := h.basicAuth.username + ":" + h.basicAuth.password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicAuthString))
		req.Header.Set("Authorization", basicAuth)
	}

	return req
}

// Get sends GET action to a requested endpoint.
func (h *HttpClient) Get(uri string) (*http.Response, error) {
	requestedUrl, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    requestedUrl,
		Header: http.Header{},
	}
	h.addDefaultHeaders(req)

	err = translateRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return resp, err
	}

	err = translateResponse(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Post sends POST action to a requested endpoint with requested body.
func (h *HttpClient) Post(uri string, requestBody []byte) (*http.Response, error) {
	requestedUrl, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	body := io.NopCloser(bytes.NewBuffer(requestBody))
	req := &http.Request{
		Method: http.MethodPost,
		URL:    requestedUrl,
		Body:   body,
		Header: http.Header{},
	}
	h.addDefaultHeaders(req)

	err = translateRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return resp, err
	}

	err = translateResponse(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Patch sends PATCH action to a requested endpoint with requested body.
func (h *HttpClient) Patch(uri string, requestBody []byte) (*http.Response, error) {
	requestedUrl, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	body := io.NopCloser(bytes.NewBuffer(requestBody))
	req := &http.Request{
		Method: http.MethodPatch,
		URL:    requestedUrl,
		Body:   body,
		Header: http.Header{},
	}
	h.addDefaultHeaders(req)

	err = translateRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return resp, err
	}

	err = translateResponse(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func translateRequest(req *http.Request) error {
	req.URL, _ = url.Parse(utils.UriConverter.DmToRedfish(req.URL.String()))

	for hk, hv := range req.Header {
		var translatedHeader []string
		for _, v := range hv {
			translatedHeader = append(translatedHeader, utils.UriConverter.DmToRedfish(v))
		}

		req.Header[hk] = translatedHeader
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}

		translatedBody := utils.UriConverter.DmToRedfish(string(body))
		req.Body = io.NopCloser(bytes.NewBuffer([]byte(translatedBody)))
	}

	return nil
}

func translateResponse(resp *http.Response) error {
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	translated := utils.UriConverter.RedfishToDm(string(responseBody))
	resp.Body = io.NopCloser(bytes.NewBuffer([]byte(translated)))

	return nil
}
