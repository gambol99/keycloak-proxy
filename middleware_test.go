/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/go-resty/resty"
	"github.com/labstack/echo/middleware"
	"github.com/stretchr/testify/assert"
)

type fakeRequest struct {
	BasicAuth               bool
	Cookies                 []*http.Cookie
	Expires                 time.Duration
	FormValues              map[string]string
	HasCookieToken          bool
	HasLogin                bool
	HasToken                bool
	Headers                 map[string]string
	Method                  string
	NotSigned               bool
	OnResponse              func(int, *resty.Request, *resty.Response)
	Password                string
	ProxyRequest            bool
	RawToken                string
	Redirects               bool
	Roles                   []string
	TokenClaims             jose.Claims
	URI                     string
	URL                     string
	Username                string
	ExpectedCode            int
	ExpectedContent         string
	ExpectedContentContains string
	ExpectedCookies         []string
	ExpectedHeaders         map[string]string
	ExpectedProxyHeaders    map[string]string
	ExpectedLocation        string
	ExpectedProxy           bool
}

type fakeProxy struct {
	config  *Config
	idp     *fakeAuthServer
	proxy   *oauthProxy
	server  *httptest.Server
	cookies map[string]*http.Cookie
}

func newFakeProxy(c *Config) *fakeProxy {
	log.SetOutput(ioutil.Discard)
	if c == nil {
		c = newFakeKeycloakConfig()
	}
	auth := newFakeAuthServer()
	c.DiscoveryURL = auth.getLocation()
	c.RevocationEndpoint = auth.getRevocationURL()
	proxy, err := newProxy(c)
	if err != nil {
		panic("failed to create fake proxy service, error: " + err.Error())
	}
	proxy.upstream = &fakeUpstreamService{}
	service := httptest.NewServer(proxy.router)
	c.RedirectionURL = service.URL
	// step: we need to update the client configs
	if proxy.client, proxy.idp, proxy.idpClient, err = newOpenIDClient(c); err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return &fakeProxy{c, auth, proxy, service, make(map[string]*http.Cookie, 0)}
}

// RunTests performs a series of requests against a fake proxy service
func (f *fakeProxy) RunTests(t *testing.T, requests []fakeRequest) {
	defer func() {
		f.idp.Close()
		f.server.Close()
	}()
	for i, c := range requests {
		var upstream fakeUpstreamResponse

		f.config.NoRedirects = !c.Redirects
		// we need to set any defaults
		if c.Method == "" {
			c.Method = http.MethodGet
		}
		// create a http client
		client := resty.New()
		request := client.SetRedirectPolicy(resty.NoRedirectPolicy()).R()

		// are we performing a oauth login beforehand
		if c.HasLogin {
			if err := f.performUserLogin(c.URI); err != nil {
				t.Errorf("case %d, unable to login to oauth server, error: %s", i, err)
				return
			}
		}
		if len(f.cookies) > 0 {
			for _, k := range f.cookies {
				client.SetCookie(k)
			}
		}
		if c.ExpectedProxy {
			request.SetResult(&upstream)
		}
		if c.ProxyRequest {
			request.SetProxy(f.server.URL)
		}
		if c.BasicAuth {
			request.SetBasicAuth(c.Username, c.Password)
		}
		if c.RawToken != "" {
			setRequestAuthentication(f.config, client, request, &c, c.RawToken)
		}
		if len(c.Cookies) > 0 {
			client.SetCookies(c.Cookies)
		}
		if len(c.Headers) > 0 {
			request.SetHeaders(c.Headers)
		}
		if c.FormValues != nil {
			request.SetFormData(c.FormValues)
		}
		if c.HasToken {
			token := newTestToken(f.idp.getLocation())
			if c.TokenClaims != nil && len(c.TokenClaims) > 0 {
				token.merge(c.TokenClaims)
			}
			if len(c.Roles) > 0 {
				token.addRealmRoles(c.Roles)
			}
			if c.Expires > 0 || c.Expires < 0 {
				token.setExpiration(time.Now().Add(c.Expires))
			}
			if c.NotSigned {
				authToken := token.getToken()
				setRequestAuthentication(f.config, client, request, &c, authToken.Encode())
			} else {
				signed, _ := f.idp.signToken(token.claims)
				setRequestAuthentication(f.config, client, request, &c, signed.Encode())
			}
		}

		// step: execute the request
		var resp *resty.Response
		var err error
		switch c.URL {
		case "":
			resp, err = request.Execute(c.Method, f.server.URL+c.URI)
		default:
			resp, err = request.Execute(c.Method, c.URL)
		}
		if err != nil {
			if !strings.Contains(err.Error(), "Auto redirect is disable") {
				assert.NoError(t, err, "case %d, unable to make request, error: %s", i, err)
				continue
			}
		}
		status := resp.StatusCode()
		if c.ExpectedCode != 0 {
			assert.Equal(t, c.ExpectedCode, status, "case %d, expected: %d, got: %d", i, c.URI, c.ExpectedCode, status)
		}
		if c.ExpectedLocation != "" {
			l := resp.Header().Get("Location")
			assert.Equal(t, c.ExpectedLocation, l, "case %d, expected location: %s, got: %s", i, c.ExpectedLocation, l)
		}
		if len(c.ExpectedHeaders) > 0 {
			for k, v := range c.ExpectedHeaders {
				e := resp.Header().Get(k)
				assert.Equal(t, v, e, "case %d, expected header %s=%s, got: %s", i, k, v, e)
			}
		}
		if c.ExpectedProxy {
			assert.NotEmpty(t, resp.Header().Get(testProxyAccepted), "case %d, did not proxy request", i)
		} else {
			assert.Empty(t, resp.Header().Get(testProxyAccepted), "case %d, should NOT proxy request", i)
		}
		if c.ExpectedProxyHeaders != nil && len(c.ExpectedProxyHeaders) > 0 {
			for k, v := range c.ExpectedProxyHeaders {
				headers := upstream.Headers
				assert.Equal(t, v, headers.Get(k), "case %d, expected proxy header %s=%s, got: %s", i, k, v, headers.Get(k))
			}
		}
		if c.ExpectedContent != "" {
			e := string(resp.Body())
			assert.Equal(t, c.ExpectedContent, e, "case %d, expected content: %s, got: %s", i, c.ExpectedContent, e)
		}
		if c.ExpectedContentContains != "" {
			e := string(resp.Body())
			assert.Contains(t, e, c.ExpectedContentContains, "case %d, expected content: %s, got: %s", i, c.ExpectedContentContains, e)
		}
		if len(c.ExpectedCookies) > 0 {
			l := len(c.ExpectedCookies)
			g := len(resp.Cookies())
			assert.Equal(t, l, g, "case %d, expected %d cookies, got: %d", i, l, g)
			for _, x := range c.ExpectedCookies {
				assert.NotNil(t, findCookie(x, resp.Cookies()), "case %d, expected cookie %s not found", i, x)
			}
		}
		if c.OnResponse != nil {
			c.OnResponse(i, request, resp)
		}
	}
}

func (f *fakeProxy) performUserLogin(uri string) error {
	resp, err := makeTestCodeFlowLogin(f.server.URL + uri)
	if err != nil {
		return err
	}
	for _, c := range resp.Cookies() {
		if c.Name == f.config.CookieAccessName || c.Name == f.config.CookieRefreshName {
			f.cookies[c.Name] = &http.Cookie{
				Name:   c.Name,
				Path:   "/",
				Domain: "127.0.0.1",
				Value:  c.Value,
			}
		}
	}

	return nil
}

func setRequestAuthentication(cfg *Config, client *resty.Client, request *resty.Request, c *fakeRequest, token string) {
	switch c.HasCookieToken {
	case true:
		client.SetCookie(&http.Cookie{
			Name:  cfg.CookieAccessName,
			Path:  "/",
			Value: token,
		})
	default:
		request.SetAuthToken(token)
	}
}

func TestMetricsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableMetrics = true
	cfg.LocalhostMetrics = true
	requests := []fakeRequest{
		{
			URI:                     oauthURL + metricsURL,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "http_request_total",
		},
		{
			URI: oauthURL + metricsURL,
			Headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			ExpectedCode: http.StatusForbidden,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestOauthRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          "/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{
			URI:          "/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestStrangeAdminRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{ // check for escaping
			URI:          "//admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "///admin/../admin//%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "/admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for prefix slashs
			URI:          "//admin/test",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for double slashs
			URI:          "/admin//test",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for double slashs no redirects
			URI:          "/admin//test",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check for dodgy url
			URI:          "//admin/../admin/test",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for it works
			URI:           "//admin/test",
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // check for it works
			URI:           "//admin//test",
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/help/../admin/test/21",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestWhiteListedRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeTestRole},
		},
		{
			URL:         "/whitelist*",
			WhiteListed: true,
			Methods:     allHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{ // check whitelisted is passed
			URI:           "/whitelist",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check whitelisted is passed
			URI:           "/whitelist/test",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/test",
			HasToken:     true,
			Roles:        []string{"nothing"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestRolePermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
		{
			URL:     "/test*",
			Methods: []string{"GET"},
			Roles:   []string{fakeTestRole},
		},
		{
			URL:     "/test_admin_role*",
			Methods: []string{"GET"},
			Roles:   []string{fakeAdminRole, fakeTestRole},
		},
		{
			URL:     "/section/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
		{
			URL:     "/section/one",
			Methods: allHTTPMethods,
			Roles:   []string{"one"},
		},
		{
			URL:     "/whitelist",
			Methods: []string{"GET"},
			Roles:   []string{},
		},
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeTestRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // check for redirect
			URI:          "/",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check with a token but not test role
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token and wrong roles
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"one", "two"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, wrong roles
			URI:          "/test",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, wrong roles, no 'get' method (5)
			URI:           "/test",
			Method:        http.MethodPost,
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"bad_role"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token
			URI:           "/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token on base
			URI:           "/",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token, not signed
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			NotSigned:    true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed
			URI:          "/admin/page",
			Method:       http.MethodPost,
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles (10)
			URI:          "/admin/page",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles
			URI:           "/admin/page",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole, fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url
			URI:          "/admin/..//admin/page",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // strange url, token
			URI:          "/admin/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"hehe"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token, role (15)
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, but good token
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, wrong roles
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token admin test role
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token but without both roles
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
			Roles:        []string{fakeAdminRole},
		},
		{ // check with a token with both roles (20)
			URI:           "/test_admin_role",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole, fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/section/test1",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/section/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole, fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/section/one",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole, fakeAdminRole},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/section/one",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"one"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestCrossSiteHandler(t *testing.T) {
	cases := []struct {
		Cors    middleware.CORSConfig
		Request fakeRequest
	}{
		{
			Cors: middleware.CORSConfig{
				AllowOrigins: []string{"*"},
			},
			Request: fakeRequest{
				URI: fakeAuthAllURL,
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: middleware.CORSConfig{
				AllowOrigins: []string{"*", "https://examples.com"},
			},
			Request: fakeRequest{
				URI: fakeAuthAllURL,
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: middleware.CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"GET", "POST"},
			},
			Request: fakeRequest{
				URI:    fakeAuthAllURL,
				Method: http.MethodOptions,
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin":  "*",
					"Access-Control-Allow-Methods": "GET,POST",
				},
			},
		},
	}

	for _, c := range cases {
		cfg := newFakeKeycloakConfig()
		cfg.CorsCredentials = c.Cors.AllowCredentials
		cfg.CorsExposedHeaders = c.Cors.ExposeHeaders
		cfg.CorsHeaders = c.Cors.AllowHeaders
		cfg.CorsMaxAge = time.Duration(time.Duration(c.Cors.MaxAge) * time.Second)
		cfg.CorsMethods = c.Cors.AllowMethods
		cfg.CorsOrigins = c.Cors.AllowOrigins

		newFakeProxy(cfg).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestCheckRefreshTokens(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableRefreshTokens = true
	cfg.EncryptionKey = "ZSeCYDUxIlhDrmPpa1Ldc7il384esSF2"
	fn := func(no int, req *resty.Request, resp *resty.Response) {
		if no == 0 {
			<-time.After(1000 * time.Millisecond)
		}
	}
	p := newFakeProxy(cfg)
	p.idp.setTokenExpiration(time.Duration(1000 * time.Millisecond))

	requests := []fakeRequest{
		{
			URI:           fakeAuthAllURL,
			HasLogin:      true,
			Redirects:     true,
			OnResponse:    fn,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:             fakeAuthAllURL,
			Redirects:       false,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			ExpectedCookies: []string{cfg.CookieAccessName},
		},
	}
	p.RunTests(t, requests)
}

func TestCustomHeadersHandler(t *testing.T) {
	requests := []struct {
		Match   []string
		Request fakeRequest
	}{
		{
			Match: []string{"subject", "userid", "email", "username"},
			Request: fakeRequest{
				URI:      fakeAuthAllURL,
				HasToken: true,
				TokenClaims: jose.Claims{
					"sub":                "test-subject",
					"username":           "rohith",
					"preferred_username": "rohith",
					"email":              "gambol99@gmail.com",
				},
				ExpectedProxyHeaders: map[string]string{
					"X-Auth-Subject":  "test-subject",
					"X-Auth-Userid":   "rohith",
					"X-Auth-Email":    "gambol99@gmail.com",
					"X-Auth-Username": "rohith",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Match: []string{"given_name", "family_name"},
			Request: fakeRequest{
				URI:      fakeAuthAllURL,
				HasToken: true,
				TokenClaims: jose.Claims{
					"email":              "gambol99@gmail.com",
					"name":               "Rohith Jayawardene",
					"family_name":        "Jayawardene",
					"preferred_username": "rjayawardene",
					"given_name":         "Rohith",
				},
				ExpectedProxyHeaders: map[string]string{
					"X-Auth-Given-Name":  "Rohith",
					"X-Auth-Family-Name": "Jayawardene",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.AddClaims = c.Match
		newFakeProxy(cfg).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*Resource{
		{
			URL:     "/admin",
			Methods: allHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:     "/test",
			Methods: []string{"GET"},
			Roles:   []string{"test"},
		},
		{
			URL:     "/either",
			Methods: allHTTPMethods,
			Roles:   []string{"admin", "test"},
		},
		{
			URL:     "/",
			Methods: allHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/admin",
			Roles:        []string{},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/admin",
			Roles:         []string{"admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/test",
			Roles:         []string{"test"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/either",
			Roles:         []string{"test", "admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/either",
			Roles:        []string{"no_roles"},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestCustomHeaders(t *testing.T) {
	uri := "/admin/test"
	requests := []struct {
		Headers map[string]string
		Request fakeRequest
	}{
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
			},
			Request: fakeRequest{
				URI:           "/test.html",
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeaderOne": "one",
				},
			},
		},
		{
			Headers: map[string]string{
				"TestHeader": "test",
			},
			Request: fakeRequest{
				URI:           uri,
				HasToken:      true,
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeader": "test",
				},
			},
		},
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
				"TestHeaderTwo": "two",
			},
			Request: fakeRequest{
				URI:           uri,
				HasToken:      true,
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeaderOne": "one",
					"TestHeaderTwo": "two",
				},
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.Resources = []*Resource{{URL: "/admin*", Methods: allHTTPMethods}}
		cfg.Headers = c.Headers
		newFakeProxy(cfg).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestRolesAdmissionHandlerClaims(t *testing.T) {
	uri := "/admin/test"
	requests := []struct {
		Matches map[string]string
		Request fakeRequest
	}{
		{
			Matches: map[string]string{"cal": "test"},
			Request: fakeRequest{
				URI:          uri,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: fakeRequest{
				URI:          uri,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: fakeRequest{
				URI:           uri,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "tes"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "not_match"},
			Request: fakeRequest{
				URI:          uri,
				HasToken:     true,
				TokenClaims:  jose.Claims{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: fakeRequest{
				URI:          uri,
				HasToken:     true,
				TokenClaims:  jose.Claims{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: fakeRequest{
				URI:      uri,
				HasToken: true,
				TokenClaims: jose.Claims{
					"item":  "tester",
					"found": "something",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": ".*"},
			Request: fakeRequest{
				URI:           uri,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*$"},
			Request: fakeRequest{
				URI:           uri,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.Resources = []*Resource{{URL: "/admin*", Methods: allHTTPMethods}}
		cfg.MatchClaims = c.Matches
		newFakeProxy(cfg).RunTests(t, []fakeRequest{c.Request})
	}
}
