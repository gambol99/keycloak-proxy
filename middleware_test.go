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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	uuid "github.com/gofrs/uuid"
	"github.com/rs/cors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"gopkg.in/resty.v1"
)

const (
	testEncryptionKey = "ZSeCYDUxIlhDrmPpa1Ldc7il384esSF2"
)

type fakeRequest struct {
	BasicAuth               bool
	Cookies                 []*http.Cookie
	Expires                 time.Duration
	FormValues              map[string]string
	Groups                  []string
	HasCookieToken          bool
	HasLogin                bool
	HasToken                bool
	Headers                 map[string]string
	Method                  string
	NotSigned               bool
	OnResponse              func(int, *resty.Request, *resty.Response)
	Password                string
	ProxyProtocol           string
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
	ExpectedCookies         map[string]string
	ExpectedHeaders         map[string]string
	ExpectedLocation        string
	ExpectedNoProxyHeaders  []string
	ExpectedProxy           bool
	ExpectedProxyHeaders    map[string]string

	// advanced test cases
	ExpectedCookiesValidator map[string]func(string) bool

	ExpectedStateUrl string
}

type fakeProxy struct {
	config  *Config
	idp     *fakeAuthServer
	proxy   *oauthProxy
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
	c.Verbose = true
	proxy, err := newProxy(c)
	if err != nil {
		panic("failed to create fake proxy service, error: " + err.Error())
	}
	proxy.log = zap.NewNop()
	proxy.upstream = &fakeUpstreamService{}
	if err = proxy.Run(); err != nil {
		panic("failed to create the proxy service, error: " + err.Error())
	}
	c.RedirectionURL = fmt.Sprintf("http://%s", proxy.listener.Addr().String())
	// step: we need to update the client configs
	if proxy.client, proxy.idp, proxy.idpClient, err = proxy.newOpenIDClient(); err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return &fakeProxy{c, auth, proxy, make(map[string]*http.Cookie)}
}

func (f *fakeProxy) getServiceURL() string {
	return fmt.Sprintf("http://%s", f.proxy.listener.Addr().String())
}

// RunTests performs a series of requests against a fake proxy service
func (f *fakeProxy) RunTests(t *testing.T, requests []fakeRequest) {
	defer func() {
		f.idp.Close()
		f.proxy.server.Close()
	}()

	for i := range requests {
		c := requests[i]
		var upstream fakeUpstreamResponse

		f.config.NoRedirects = !c.Redirects
		// we need to set any defaults
		if c.Method == "" {
			c.Method = http.MethodGet
		}
		// create a http client
		client := resty.New()
		request := client.SetRedirectPolicy(resty.NoRedirectPolicy()).R()

		if c.ProxyProtocol != "" {
			client.SetTransport(&http.Transport{
				Dial: func(network, addr string) (net.Conn, error) {
					conn, err := net.Dial("tcp", addr)
					if err != nil {
						return nil, err
					}
					header := fmt.Sprintf("PROXY TCP4 %s 10.0.0.1 1000 2000\r\n", c.ProxyProtocol)
					_, _ = conn.Write([]byte(header))

					return conn, nil
				},
			})
		}

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
			client.SetProxy(f.getServiceURL())
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
			if len(c.Groups) > 0 {
				token.addGroups(c.Groups)
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
			resp, err = request.Execute(c.Method, f.getServiceURL()+c.URI)
		default:
			resp, err = request.Execute(c.Method, c.URL)
		}
		if err != nil {
			if !strings.Contains(err.Error(), "auto redirect is disabled") {
				assert.NoError(t, err, "case %d, unable to make request, error: %s", i, err)
				continue
			}
		}
		status := resp.StatusCode()
		if c.ExpectedCode != 0 {
			assert.Equal(t, c.ExpectedCode, status, "case %d, expected status code: %d, got: %d", i, c.ExpectedCode, status)
		}
		if c.ExpectedLocation != "" || c.ExpectedStateUrl != "" {
			l, _ := url.Parse(resp.Header().Get("Location"))
			if c.ExpectedLocation != "" {
				assert.True(t, strings.Contains(l.String(), c.ExpectedLocation), "expected location to contain %s", l.String())
			}
			stateStr := l.Query().Get("state")
			if stateStr != "" {
				stateParam := StateParameter{}
				err := json.Unmarshal([]byte(stateStr), &stateParam)
				if err != nil {
					assert.Fail(t, "failed to deserialise state parameter from json, got: %s with error %s", stateStr, err)
				}

				if c.ExpectedStateUrl != "" {
					assert.Equal(t, c.ExpectedStateUrl, stateParam.Url, "expected state url to contain %s", stateParam.Url)
				}

				state, err := uuid.FromString(stateParam.Token)
				if err != nil {
					assert.Fail(t, "expected state parameter with valid UUID, got: %s with error %s", state.String(), err)
				}
			}
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
				switch v {
				case "":
					assert.NotEmpty(t, headers.Get(k), "case %d, expected the proxy header: %s to exist", i, k)
				default:
					assert.Equal(t, v, headers.Get(k), "case %d, expected proxy header %s=%s, got: %s", i, k, v, headers.Get(k))
				}
			}
		}
		if len(c.ExpectedNoProxyHeaders) > 0 {
			for _, k := range c.ExpectedNoProxyHeaders {
				assert.Empty(t, upstream.Headers.Get(k), "case %d, header: %s was not expected to exist", i, k)
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
			for k, v := range c.ExpectedCookies {
				cookie := findCookie(k, resp.Cookies())
				if !assert.NotNil(t, cookie, "case %d, expected cookie %s not found", i, k) {
					continue
				}
				if v != "" {
					assert.Equal(t, cookie.Value, v, "case %d, expected cookie value: %s, got: %s", i, v, cookie.Value)
				}
			}
			for k, v := range c.ExpectedCookiesValidator {
				cookie := findCookie(k, resp.Cookies())
				if !assert.NotNil(t, cookie, "case %d, expected cookie %s not found", i, k) {
					continue
				}
				if v != nil {
					assert.True(t, v(cookie.Value), "case %d, invalid cookie value: %s", i, cookie.Value)
				}
			}
		}
		if c.OnResponse != nil {
			c.OnResponse(i, request, resp)
		}
	}
}

func (f *fakeProxy) performUserLogin(uri string) error {
	resp, err := makeTestCodeFlowLogin(f.getServiceURL() + uri)
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
	defer resp.Body.Close()

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
			URI: cfg.WithOAuthURI(metricsURL),
			Headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			ExpectedCode: http.StatusForbidden,
		},
		// Some request must run before this one to generate request status numbers
		{
			URI:                     cfg.WithOAuthURI(metricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "proxy_request_status_total",
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
			ExpectedCode: http.StatusSeeOther,
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

func TestOauthRequestsWithBaseURI(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.BaseURI = "/base-uri"
	requests := []fakeRequest{
		{
			URI:          "/base-uri/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{
			URI:          "/base-uri/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/base-uri/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:           "/oauth/authorize",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/oauth/callback",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/oauth/health",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestMethodExclusions(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/post",
			Methods: []string{http.MethodPost, http.MethodPut},
		},
	}
	requests := []fakeRequest{
		{ // we should get a 401
			URI:          "/post",
			Method:       http.MethodPost,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // we should be permitted
			URI:           "/post",
			Method:        http.MethodGet,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestPreserveURLEncoding(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableLogging = true
	cfg.Resources = []*Resource{
		{
			URL:     "/api/v2/*",
			Methods: allHTTPMethods,
			Roles:   []string{"dev"},
		},
		{
			URL:     "/api/v1/auth*",
			Methods: allHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:         "/api/v1/*",
			Methods:     allHTTPMethods,
			WhiteListed: true,
		},
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{"user"},
		},
	}
	requests := []fakeRequest{
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
		{ // See KEYCLOAK-10864
			URI:                     "/administrativeMonitor/hudson.diagnosis.ReverseProxySetupMonitor/testForReverseProxySetup/https%3A%2F%2Flocalhost%3A6001%2Fmanage/",
			ExpectedContentContains: `"uri":"/administrativeMonitor/hudson.diagnosis.ReverseProxySetupMonitor/testForReverseProxySetup/https%3A%2F%2Flocalhost%3A6001%2Fmanage/"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // See KEYCLOAK-11276
			URI:                     "/iiif/2/edepot_local:ST%2F00001%2FST00005_00001.jpg/full/1000,/0/default.png",
			ExpectedContentContains: `"uri":"/iiif/2/edepot_local:ST%2F00001%2FST00005_00001.jpg/full/1000,/0/default.png"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // See KEYCLOAK-13315
			URI:                     "/rabbitmqui/%2F/replicate-to-central",
			ExpectedContentContains: `"uri":"/rabbitmqui/%2F/replicate-to-central"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // should work
			URI:           "/api/v1/auth",
			HasToken:      true,
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // should work
			URI:                     "/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			ExpectedContentContains: `"uri":"/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth"`,
			HasToken:                true,
			Roles:                   []string{"admin"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{
			URI:          "/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			HasToken:     true,
			Roles:        []string{"user"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // should work
			URI:                     "/api/v3/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			ExpectedContentContains: `"uri":"/api/v3/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
	}

	newFakeProxy(cfg).RunTests(t, requests)
}

func TestStrangeRoutingError(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/api/v1/events/123456789",
			Methods: allHTTPMethods,
			Roles:   []string{"user"},
		},
		{
			URL:     "/api/v1/events/404",
			Methods: allHTTPMethods,
			Roles:   []string{"monitoring"},
		},
		{
			URL:     "/api/v1/audit/*",
			Methods: allHTTPMethods,
			Roles:   []string{"auditor", "dev"},
		},
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{"dev"},
		},
	}
	requests := []fakeRequest{
		{ // should work
			URI:                     "/api/v1/events/123456789",
			HasToken:                true,
			Redirects:               true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: `"uri":"/api/v1/events/123456789"`,
		},
		{ // should break with bad role
			URI:          "/api/v1/events/123456789",
			HasToken:     true,
			Redirects:    true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // good
			URI:           "/api/v1/events/404",
			HasToken:      true,
			Redirects:     false,
			Roles:         []string{"monitoring", "test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // this should fail with no roles - hits catch all
			URI:          "/api/v1/event/1000",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // this should fail with bad role - hits catch all
			URI:          "/api/v1/event/1000",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // should work with catch-all
			URI:           "/api/v1/event/1000",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"dev"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}

	newFakeProxy(cfg).RunTests(t, requests)
}

func TestNoProxyingRequests(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{ // check for escaping
			URI:          "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/../%2e",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
	}
	newFakeProxy(c).RunTests(t, requests)
}

const testAdminURI = "/admin/test"

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
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "///admin/../admin//%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for prefix slashs
			URI:          "/" + testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for double slashs
			URI:          testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for double slashs no redirects
			URI:          "/admin//test",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check for dodgy url
			URI:          "//admin/.." + testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for it works
			URI:           "/" + testAdminURI,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // check for is doens't work
			URI:          "//admin//test",
			HasToken:     true,
			Roles:        []string{"bad"},
			ExpectedCode: http.StatusForbidden,
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

func TestRequireAnyRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:            "/require_any_role/*",
			Methods:        allHTTPMethods,
			RequireAnyRole: true,
			Roles:          []string{"admin", "guest"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/require_any_role/test",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:           "/require_any_role/test",
			HasToken:      true,
			Roles:         []string{"guest"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/require_any_role/test",
			HasToken:     true,
			Roles:        []string{"guest1"},
			ExpectedCode: http.StatusForbidden,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestGroupPermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/with_role_and_group*",
			Methods: allHTTPMethods,
			Groups:  []string{"admin"},
			Roles:   []string{"admin"},
		},
		{
			URL:     "/with_group*",
			Methods: allHTTPMethods,
			Groups:  []string{"admin"},
		},
		{
			URL:     "/with_many_groups*",
			Methods: allHTTPMethods,
			Groups:  []string{"admin", "user", "tester"},
		},
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{"user"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Roles:        []string{"admin"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Groups:       []string{"admin"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_role_and_group/test",
			HasToken:      true,
			Groups:        []string{"admin"},
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_groupdd",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"test", "admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/with_many_groups/test",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"user"},
			Roles:         []string{"test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"tester", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"bad", "user"},
			ExpectedProxy: true,
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
			ExpectedCode: http.StatusSeeOther,
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
		{ // token, but post method
			URI:           "/test",
			Method:        http.MethodPost,
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
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
		Cors    cors.Options
		Request fakeRequest
	}{
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*"},
			},
			Request: fakeRequest{
				URI: fakeAuthAllURL,
				Headers: map[string]string{
					"Origin": "127.0.0.1",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*", "https://examples.com"},
			},
			Request: fakeRequest{
				URI: fakeAuthAllURL,
				Headers: map[string]string{
					"Origin": "127.0.0.1",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST"},
			},
			Request: fakeRequest{
				URI:    fakeAuthAllURL,
				Method: http.MethodOptions,
				Headers: map[string]string{
					"Origin":                        "127.0.0.1",
					"Access-Control-Request-Method": "GET",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin":  "*",
					"Access-Control-Allow-Methods": "GET",
				},
			},
		},
	}

	for _, c := range cases {
		cfg := newFakeKeycloakConfig()
		cfg.CorsCredentials = c.Cors.AllowCredentials
		cfg.CorsExposedHeaders = c.Cors.ExposedHeaders
		cfg.CorsHeaders = c.Cors.AllowedHeaders
		cfg.CorsMaxAge = time.Duration(c.Cors.MaxAge) * time.Second
		cfg.CorsMethods = c.Cors.AllowedMethods
		cfg.CorsOrigins = c.Cors.AllowedOrigins

		newFakeProxy(cfg).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestCheckRefreshTokens(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableRefreshTokens = true
	cfg.EncryptionKey = testEncryptionKey
	fn := func(no int, req *resty.Request, resp *resty.Response) {
		if no == 0 {
			<-time.After(1000 * time.Millisecond)
		}
	}
	p := newFakeProxy(cfg)
	p.idp.setTokenExpiration(1000 * time.Millisecond)

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
			ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
		},
	}
	p.RunTests(t, requests)
}

func TestCheckEncryptedCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableRefreshTokens = true
	cfg.EnableEncryptedToken = true
	cfg.Verbose = true
	cfg.EnableLogging = true
	cfg.EncryptionKey = testEncryptionKey
	testEncryptedToken(t, cfg)
}

func TestCheckForcedEncryptedCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableRefreshTokens = true
	cfg.EnableEncryptedToken = false
	cfg.ForceEncryptedCookie = true
	cfg.Verbose = true
	cfg.EnableLogging = true
	cfg.EncryptionKey = testEncryptionKey
	testEncryptedToken(t, cfg)
}

func testEncryptedToken(t *testing.T, cfg *Config) {
	fn := func(no int, req *resty.Request, resp *resty.Response) {
		if no == 0 {
			<-time.After(1000 * time.Millisecond)
		}
	}
	val := func(value string) bool {
		// check the cookie value is an encrypted token
		accessToken, err := decodeText(value, cfg.EncryptionKey)
		if err != nil {
			return false
		}
		jwt, err := jose.ParseJWT(accessToken)
		if err != nil {
			return false
		}
		claims, err := jwt.Claims()
		if err != nil {
			return false
		}
		return assert.Contains(t, claims, "aud") && assert.Contains(t, claims, "email")
	}
	p := newFakeProxy(cfg)
	p.idp.setTokenExpiration(1000 * time.Millisecond)

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
			URI:                      fakeAuthAllURL,
			Redirects:                false,
			ExpectedProxy:            true,
			ExpectedCode:             http.StatusOK,
			ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
			ExpectedCookiesValidator: map[string]func(string) bool{cfg.CookieAccessName: val},
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
			Match: []string{"given_name", "family_name", "preferred_username|Custom-Header"},
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
					"Custom-Header":      "rjayawardene",
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

// check to see if custom headers are hitting the upstream
func TestCustomHeaders(t *testing.T) {
	requests := []struct {
		Headers map[string]string
		Request fakeRequest
	}{
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
			},
			Request: fakeRequest{
				URI:           "/gambol99.htm",
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
				URI:           testAdminURI,
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
				URI:           testAdminURI,
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
	requests := []struct {
		Matches map[string]string
		Request fakeRequest
	}{
		// jose.StringClaim test
		{
			Matches: map[string]string{"cal": "test"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "tes"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "not_match"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				TokenClaims:  jose.Claims{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				TokenClaims:  jose.Claims{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: fakeRequest{
				URI:      testAdminURI,
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
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*$"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		// jose.StringsClaim test
		{
			Matches: map[string]string{"item": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": []string{"nonMatchingClaim", "test", "anotherNonMatching"}},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": []string{"1test", "2test", "3test"}},
				ExpectedProxy: false,
				ExpectedCode:  http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   jose.Claims{"item": []string{}},
				ExpectedProxy: false,
				ExpectedCode:  http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{
				"item1": "^t.*t",
				"item2": "^another",
			},
			Request: fakeRequest{
				URI:      testAdminURI,
				HasToken: true,
				TokenClaims: jose.Claims{
					"item1": []string{"randomItem", "test"},
					"item2": []string{"randomItem", "anotherItem"},
					"item3": []string{"randomItem2", "anotherItem3"},
				},
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

func TestGzipCompression(t *testing.T) {
	requests := []struct {
		EnableCompression bool
		Request           fakeRequest
	}{
		{
			EnableCompression: true,
			Request: fakeRequest{
				URI:           "/gambol99.htm",
				ExpectedProxy: true,
				Headers: map[string]string{
					"Accept-Encoding": "gzip, deflate, br",
				},
				ExpectedHeaders: map[string]string{
					"Content-Encoding": "gzip",
				},
			},
		},
		{
			EnableCompression: true,
			Request: fakeRequest{
				URI:           testAdminURI,
				ExpectedProxy: false,
				Headers: map[string]string{
					"Accept-Encoding": "gzip, deflate, br",
				},
				ExpectedHeaders: map[string]string{
					"Content-Encoding": "gzip",
				},
			},
		},
		{
			EnableCompression: false,
			Request: fakeRequest{
				URI:           "/gambol99.htm",
				ExpectedProxy: true,
				Headers: map[string]string{
					"Accept-Encoding": "gzip, deflate, br",
				},
				ExpectedNoProxyHeaders: []string{"Content-Encoding"},
			},
		},
		{
			EnableCompression: false,
			Request: fakeRequest{
				URI:           testAdminURI,
				ExpectedProxy: false,
				Headers: map[string]string{
					"Accept-Encoding": "gzip, deflate, br",
				},
				ExpectedNoProxyHeaders: []string{"Content-Encoding"},
			},
		},
	}

	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.Resources = []*Resource{{URL: "/admin*", Methods: allHTTPMethods}}
		cfg.EnableCompression = c.EnableCompression
		newFakeProxy(cfg).RunTests(t, []fakeRequest{c.Request})
	}
}
