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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/gambol99/go-oidc/oidc"

	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

// openIDProxy is the server component
type openIDProxy struct {
	config *Config
	// the gin service
	router *gin.Engine
	// the oidc provider config
	openIDConfig oidc.ClientConfig
	// the oidc client
	openIDClient *oidc.Client
	// the proxy client
	proxy reverseProxy
	// the upstream endpoint
	upstreamURL *url.URL
}

type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

// newProxy create's a new oidc proxy from configuration
func newProxy(cfg *Config) (*openIDProxy, error) {
	// step: set the logging level
	if cfg.LogJSONFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if cfg.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("starting %s, version: %s, author: %s", prog, version, author)

	// step: parse the upstream endpoint
	upstreamURL, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}

	// step: initialize the reverse http proxy
	reverse, err := initializeReverseProxy(upstreamURL)
	if err != nil {
		return nil, err
	}

	// step: create a proxy service
	service := &openIDProxy{
		config:      cfg,
		proxy:       reverse,
		upstreamURL: upstreamURL,
	}

	// step: initialize the openid client
	if cfg.SkipTokenVerification {
		log.Infof("TESTING ONLY CONFIG - the verification of the token have been disabled")

	} else {
		client, clientCfg, err := initializeOpenID(cfg.DiscoveryURL, cfg.ClientID, cfg.Secret, cfg.RedirectionURL, cfg.Scopes)
		if err != nil {
			return nil, err
		}
		service.openIDConfig = clientCfg
		service.openIDClient = client
	}

	// step: initialize the gin router
	router := gin.New()
	service.router = router
	// step: load the templates
	service.initializeTemplates()
	for _, resource := range cfg.Resources {
		log.Infof("protecting resources under uri: %s", resource)
	}
	for name, value := range cfg.ClaimsMatch {
		log.Infof("the token must container the claim: %s, required: %s", name, value)
	}

	service.initializeRouter()

	return service, nil
}

// initializeRouter sets up the gin routing
func (r KeycloakProxy) initializeRouter() {
	r.router.Use(gin.Recovery())
	// step: are we logging the traffic?
	if r.config.LogRequests {
		r.router.Use(r.loggingHandler())
	}
	// step: if gin release production
	if os.Getenv("GIN_MODE") == "release" {
		log.Infof("enabling the security handler for release mode")
		r.router.Use(r.securityHandler())
	}

	// step: add the routing
	r.router.GET(authorizationURL, r.oauthAuthorizationHandler)
	r.router.GET(callbackURL, r.oauthCallbackHandler)
	r.router.GET(healthURL, r.healthHandler)
	r.router.Use(r.entryPointHandler(), r.authenticationHandler(), r.admissionHandler())
}

// initializeTemplates loads the custom template
func (r *openIDProxy) initializeTemplates() {
	var list []string

	if r.config.SignInPage != "" {
		log.Debugf("loading the custom sign in page: %s", r.config.SignInPage)
		list = append(list, r.config.SignInPage)
	}
	if r.config.ForbiddenPage != "" {
		log.Debugf("loading the custom sign forbidden page: %s", r.config.ForbiddenPage)
		list = append(list, r.config.ForbiddenPage)
	}

	if len(list) > 0 {
		r.router.LoadHTMLFiles(list...)
	}
}

// Run starts the proxy service
func (r *openIDProxy) Run() error {
	tlsConfig := &tls.Config{}

	// step: are we doing mutual tls?
	if r.config.TLSCaCertificate != "" {
		log.Infof("enabling mutual tls, reading in the ca: %s", r.config.TLSCaCertificate)

		caCert, err := ioutil.ReadFile(r.config.TLSCaCertificate)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	go func() {
		log.Infof("keycloak proxy service starting on %s", r.config.Listen)

		var err error
		if r.config.TLSCertificate == "" {
			err = r.router.Run(r.config.Listen)
		} else {
			server := &http.Server{
				Addr:      r.config.Listen,
				Handler:   r.router,
				TLSConfig: tlsConfig,
			}
			err = server.ListenAndServeTLS(r.config.TLSCertificate, r.config.TLSPrivateKey)
		}
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Fatalf("failed to start the service")
		}
	}()

	return nil
}

// redirectToURL redirects the user and aborts the context
func (r openIDProxy) redirectToURL(url string, cx *gin.Context) {
	cx.Redirect(http.StatusTemporaryRedirect, url)
	cx.Abort()
}

// accessForbidden redirects the user to the forbidden page
func (r openIDProxy) accessForbidden(cx *gin.Context) {
	// step: do we have a custom forbidden page
	if r.config.hasForbiddenPage() {
		cx.HTML(http.StatusForbidden, r.config.ForbiddenPage, r.config.TagData)
		cx.Abort()
		return
	}

	cx.AbortWithStatus(http.StatusForbidden)
	cx.Abort()
}

// redirectToAuthorization redirects the user to authorization handler
func (r openIDProxy) redirectToAuthorization(cx *gin.Context) {
	// step: add a state referrer to the authorization page
	authQuery := fmt.Sprintf("?state=%s", cx.Request.URL.String())

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		log.Errorf("refusing to redirection to authorization endpoint, skip token verification switched on")
		r.accessForbidden(cx)
		return
	}

	r.redirectToURL(authorizationURL+authQuery, cx)
}

// tryUpdateConnection attempt to upgrade the connection to a http pdy stream
func (r *openIDProxy) tryUpdateConnection(cx *gin.Context) error {
	// step: dial the endpoint
	tlsConn, err := tryDialEndpoint(r.upstreamURL)
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// step: we need to hijack the underlining client connection
	clientConn, _, err := cx.Writer.(http.Hijacker).Hijack()
	if err != nil {

	}
	defer clientConn.Close()

	// step: write the request to upstream
	if err = cx.Request.Write(tlsConn); err != nil {
		return err
	}

	// step: copy the date between client and upstream endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	go transferBytes(tlsConn, clientConn, &wg)
	go transferBytes(clientConn, tlsConn, &wg)
	wg.Wait()

	return nil
}
