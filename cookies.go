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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	uuid "github.com/gofrs/uuid"
)

// SameSite cookie config options
const (
	SameSiteStrict = "Strict"
	SameSiteLax    = "Lax"
	SameSiteNone   = "None"
)

// dropCookie drops a cookie into the response
func (r *oauthProxy) dropCookie(w http.ResponseWriter, host, name, value string, duration time.Duration) {
	// step: default to the host header, else the config domain
	domain := ""
	if r.config.CookieDomain != "" {
		domain = r.config.CookieDomain
	}
	path := r.config.BaseURI
	if path == "" {
		path = "/"
	}
	cookie := &http.Cookie{
		Domain:   domain,
		HttpOnly: r.config.HTTPOnlyCookie,
		Name:     name,
		Path:     path,
		Secure:   r.config.SecureCookie,
		Value:    value,
	}
	if !r.config.EnableSessionCookies && duration != 0 {
		cookie.Expires = time.Now().Add(duration)
	}

	switch r.config.SameSiteCookie {
	case SameSiteStrict:
		cookie.SameSite = http.SameSiteStrictMode
	case SameSiteLax:
		cookie.SameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, cookie)
}

// maxCookieChunkSize calculates max cookie chunk size, which can be used for cookie value
func (r *oauthProxy) getMaxCookieChunkLength(req *http.Request, cookieName string) int {
	maxCookieChunkLength := 4069 - len(cookieName)
	if r.config.CookieDomain != "" {
		maxCookieChunkLength -= len(r.config.CookieDomain)
	} else {
		maxCookieChunkLength -= len(strings.Split(req.Host, ":")[0])
	}
	if r.config.HTTPOnlyCookie {
		maxCookieChunkLength -= len("HttpOnly; ")
	}
	if !r.config.EnableSessionCookies {
		maxCookieChunkLength -= len("Expires=Mon, 02 Jan 2006 03:04:05 MST; ")
	}
	switch r.config.SameSiteCookie {
	case SameSiteStrict:
		maxCookieChunkLength -= len("SameSite=Strict ")
	case SameSiteLax:
		maxCookieChunkLength -= len("SameSite=Lax ")
	}
	if r.config.SecureCookie {
		maxCookieChunkLength -= len("Secure")
	}
	return maxCookieChunkLength
}

// dropCookieWithChunks drops a cookie from the response, taking into account possible chunks
func (r *oauthProxy) dropCookieWithChunks(req *http.Request, w http.ResponseWriter, name, value string, duration time.Duration) {
	maxCookieChunkLength := r.getMaxCookieChunkLength(req, name)
	if len(value) <= maxCookieChunkLength {
		r.dropCookie(w, req.Host, name, value, duration)
	} else {
		// write divided cookies because payload is too long for single cookie
		r.dropCookie(w, req.Host, name, value[0:maxCookieChunkLength], duration)
		for i := maxCookieChunkLength; i < len(value); i += maxCookieChunkLength {
			end := i + maxCookieChunkLength
			if end > len(value) {
				end = len(value)
			}
			r.dropCookie(w, req.Host, name+"-"+strconv.Itoa(i/maxCookieChunkLength), value[i:end], duration)
		}
	}
}

// dropAccessTokenCookie drops a access token cookie from the response
func (r *oauthProxy) dropAccessTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	r.dropCookieWithChunks(req, w, r.config.CookieAccessName, value, duration)
}

// dropRefreshTokenCookie drops a refresh token cookie from the response
func (r *oauthProxy) dropRefreshTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	r.dropCookieWithChunks(req, w, r.config.CookieRefreshName, value, duration)
}

type StateParameter struct {
	Token string `json:"token"`
	Url   string `json:"url"`
}

// writeStateParameterCookie sets a state parameter cookie into the response
func (r *oauthProxy) writeStateParameterCookie(req *http.Request, w http.ResponseWriter) (string, error) {
	uuid, err := uuid.NewV4()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	requestURI := base64.StdEncoding.EncodeToString([]byte(req.URL.RequestURI()))
	r.dropCookie(w, req.Host, requestURICookie, requestURI, 0)
	r.dropCookie(w, req.Host, requestStateCookie, uuid.String(), 0)

	stateParam := StateParameter{Token: uuid.String(),
		Url: req.URL.RequestURI()}
	output, err := json.Marshal(stateParam)

	return string(output), err
}

// clearAllCookies is just a helper function for the below
func (r *oauthProxy) clearAllCookies(req *http.Request, w http.ResponseWriter) {
	r.clearAccessTokenCookie(req, w)
	r.clearRefreshTokenCookie(req, w)
}

// clearRefreshSessionCookie clears the session cookie
func (r *oauthProxy) clearRefreshTokenCookie(req *http.Request, w http.ResponseWriter) {
	r.dropCookie(w, req.Host, r.config.CookieRefreshName, "", -10*time.Hour)

	// clear divided cookies
	for i := 1; i < 600; i++ {
		var _, err = req.Cookie(r.config.CookieRefreshName + "-" + strconv.Itoa(i))
		if err == nil {
			r.dropCookie(w, req.Host, r.config.CookieRefreshName+"-"+strconv.Itoa(i), "", -10*time.Hour)
		} else {
			break
		}
	}
}

// clearAccessTokenCookie clears the session cookie
func (r *oauthProxy) clearAccessTokenCookie(req *http.Request, w http.ResponseWriter) {
	r.dropCookie(w, req.Host, r.config.CookieAccessName, "", -10*time.Hour)

	// clear divided cookies
	for i := 1; i < len(req.Cookies()); i++ {
		var _, err = req.Cookie(r.config.CookieAccessName + "-" + strconv.Itoa(i))
		if err == nil {
			r.dropCookie(w, req.Host, r.config.CookieAccessName+"-"+strconv.Itoa(i), "", -10*time.Hour)
		} else {
			break
		}
	}
}
