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
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestDebugHandler(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.Resources = make([]*Resource, 0)
	c.EnableProfiling = true
	requests := []fakeRequest{
		{URI: "/debug/pprof/no_there", ExpectedCode: http.StatusNotFound},
		{URI: "/debug/pprof/heap", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/goroutine", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/block", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/threadcreate", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/cmdline", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/trace", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", Method: http.MethodPost, ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", Method: http.MethodPost, ExpectedCode: http.StatusOK},
	}
	newFakeProxy(c).RunTests(t, requests)
}

func TestExpirationHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	uri := cfg.WithOAuthURI(expiredURL)
	requests := []fakeRequest{
		{
			URI:          uri,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			HasToken:     true,
			Expires:      -48 * time.Hour,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			HasToken:     true,
			Expires:      14 * time.Hour,
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func TestOauthRequestNotProxying(t *testing.T) {
	requests := []fakeRequest{
		{URI: "/oauth/test"},
		{URI: "/oauth/..//oauth/test/"},
		{URI: "/oauth/expired", Method: http.MethodPost, ExpectedCode: http.StatusMethodNotAllowed},
		{URI: "/oauth/expiring", Method: http.MethodPost},
		{URI: "/oauth%2F///../test%2F%2Foauth"},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func TestLoginHandlerDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableLoginHandler = false
	requests := []fakeRequest{
		{URI: c.WithOAuthURI(loginURL), Method: http.MethodPost, ExpectedCode: http.StatusNotImplemented},
		{URI: c.WithOAuthURI(loginURL), ExpectedCode: http.StatusMethodNotAllowed},
	}
	newFakeProxy(c).RunTests(t, requests)
}

func TestLoginHandlerNotDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableLoginHandler = true
	requests := []fakeRequest{
		{URI: "/oauth/login", Method: http.MethodPost, ExpectedCode: http.StatusBadRequest},
	}
	newFakeProxy(c).RunTests(t, requests)
}

func TestLoginHandler(t *testing.T) {
	uri := newFakeKeycloakConfig().WithOAuthURI(loginURL)
	requests := []fakeRequest{
		{
			URI:          uri,
			Method:       http.MethodPost,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			Method:       http.MethodPost,
			FormValues:   map[string]string{"username": "test"},
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			Method:       http.MethodPost,
			FormValues:   map[string]string{"password": "test"},
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:    uri,
			Method: http.MethodPost,
			FormValues: map[string]string{
				"password": "test",
				"username": "test",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			URI:    uri,
			Method: http.MethodPost,
			FormValues: map[string]string{
				"password": "test",
				"username": "notmypassword",
			},
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func TestLogoutHandlerBadRequest(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:          newFakeKeycloakConfig().WithOAuthURI(logoutURL),
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func TestLogoutHandlerBadToken(t *testing.T) {
	c := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          c.WithOAuthURI(logoutURL),
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:            c.WithOAuthURI(logoutURL),
			HasCookieToken: true,
			RawToken:       "this.is.a.bad.token",
			ExpectedCode:   http.StatusUnauthorized,
		},
		{
			URI:          c.WithOAuthURI(logoutURL),
			RawToken:     "this.is.a.bad.token",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func TestLogoutHandlerGood(t *testing.T) {
	c := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          c.WithOAuthURI(logoutURL),
			HasToken:     true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:              c.WithOAuthURI(logoutURL) + "?redirect=http://example.com",
			HasToken:         true,
			ExpectedCode:     http.StatusSeeOther,
			ExpectedLocation: "http://example.com",
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func TestTokenHandler(t *testing.T) {
	uri := newFakeKeycloakConfig().WithOAuthURI(tokenURL)
	goodToken := newTestToken("example").getToken()
	requests := []fakeRequest{
		{
			URI:          uri,
			HasToken:     true,
			RawToken:     (&goodToken).Encode(),
			ExpectedCode: http.StatusOK,
		},
		{
			URI:          uri,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			RawToken:     "niothing",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:            uri,
			HasToken:       true,
			HasCookieToken: true,
			ExpectedCode:   http.StatusOK,
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func TestServiceRedirect(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedCode:     http.StatusSeeOther,
			ExpectedLocation: "/oauth/authorize?state",
		},
		{
			URI:          "/admin",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func TestAuthorizationURLWithSkipToken(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.SkipTokenVerification = true
	newFakeProxy(c).RunTests(t, []fakeRequest{
		{
			URI:          c.WithOAuthURI(authorizationURL),
			ExpectedCode: http.StatusNotAcceptable,
		},
	})
}

func TestAuthorizationURL(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              "/admin/test",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              "/help/../admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              "/admin?test=yes&test1=test",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:          "/oauth/test",
			Redirects:    true,
			ExpectedCode: http.StatusNotFound,
		},
		{
			URI:          "/oauth/callback/..//test",
			Redirects:    true,
			ExpectedCode: http.StatusNotFound,
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}

func getStateQueryParameter(t *testing.T, redirectUrl string) string {
	stateParameter := StateParameter{Url: redirectUrl}
	res, err := json.Marshal(stateParameter)
	if err != nil {
		t.Fatalf("Failed to marshall state parameter to string: %s", err)
		return ""
	}
	return url.QueryEscape(string(res))
}

func TestCallbackURL(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          cfg.WithOAuthURI(callbackURL),
			Method:       http.MethodPost,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
		{
			URI:          cfg.WithOAuthURI(callbackURL),
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:              cfg.WithOAuthURI(callbackURL) + "?code=fake",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              cfg.WithOAuthURI(callbackURL) + "?code=fake&state=" + getStateQueryParameter(t, "/admin?some-param=true&some-other=false"),
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/admin?some-param=true&some-other=false",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              cfg.WithOAuthURI(callbackURL) + "?code=fake&state=" + getStateQueryParameter(t, "/"),
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusSeeOther,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

func TestHealthHandler(t *testing.T) {
	c := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:             c.WithOAuthURI(healthURL),
			ExpectedCode:    http.StatusOK,
			ExpectedContent: "OK\n",
		},
		{
			URI:          c.WithOAuthURI(healthURL),
			Method:       http.MethodHead,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
	}
	newFakeProxy(nil).RunTests(t, requests)
}
