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

package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	httplog "log"

	"github.com/gambol99/keycloak-proxy/pkg/api"
	"github.com/gambol99/keycloak-proxy/pkg/certs"
	"github.com/gambol99/keycloak-proxy/pkg/certs/letsencrypt"
	"github.com/gambol99/keycloak-proxy/pkg/certs/rotate"
	"github.com/gambol99/keycloak-proxy/pkg/constants"
	"github.com/gambol99/keycloak-proxy/pkg/store"
	"github.com/gambol99/keycloak-proxy/pkg/utils"

	"github.com/armon/go-proxyproto"
	"github.com/gambol99/go-oidc/oidc"
	"github.com/gambol99/goproxy"
	"github.com/pressly/chi"
	"github.com/pressly/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/cors"
	"go.uber.org/zap"
)

type oauthProxy struct {
	client         *oidc.Client
	config         *api.Config
	endpoint       *url.URL
	idp            oidc.ProviderConfig
	idpClient      *http.Client
	listener       net.Listener
	log            *zap.Logger
	metricsHandler http.Handler
	router         http.Handler
	server         *http.Server
	store          store.Storage
	templates      *template.Template
	upstream       reverseProxy
}

func init() {
	time.LoadLocation("UTC")             // ensure all time is in UTC
	runtime.GOMAXPROCS(runtime.NumCPU()) // set the core
}

// New create's a new proxy from configuration
func New(config *api.Config) (*oauthProxy, error) {
	// create the service logger
	log, err := createLogger(config)
	if err != nil {
		return nil, err
	}

	log.Info("starting the service", zap.String("prog", constants.Prog), zap.String("author", constants.Author), zap.String("version", constants.Version))
	svc := &oauthProxy{
		config:         config,
		log:            log,
		metricsHandler: prometheus.Handler(),
	}

	// parse the upstream endpoint
	if config.Upstream != "" {
		if svc.endpoint, err = url.Parse(config.Upstream); err != nil {
			return nil, err
		}
	}

	// initialize the store if any
	if config.StoreURL != "" {
		if svc.store, err = store.New(config.StoreURL); err != nil {
			return nil, err
		}
	}

	// initialize the openid client
	if !config.SkipTokenVerification {
		if svc.client, svc.idp, svc.idpClient, err = svc.newOpenIDClient(); err != nil {
			return nil, err
		}
	} else {
		log.Warn("TESTING ONLY CONFIG - the verification of the token have been disabled")
	}

	if config.ClientID == "" && config.ClientSecret == "" {
		log.Warn("client credentials are not set, depending on provider (confidential|public) you might be unable to auth")
	}

	// are we running in forwarding mode?
	if config.EnableForwarding {
		if err := svc.createForwardingProxy(); err != nil {
			return nil, err
		}
	} else {
		if err := svc.createReverseProxy(); err != nil {
			return nil, err
		}
	}

	return svc, nil
}

// createLogger is responsible for creating the service logger
func createLogger(config *api.Config) (*zap.Logger, error) {
	httplog.SetOutput(ioutil.Discard) // disable the http logger
	if config.DisableAllLogging {
		return zap.NewNop(), nil
	}

	c := zap.NewProductionConfig()
	c.DisableStacktrace = true
	c.DisableCaller = true
	// are we enabling json logging?
	if !config.EnableJSONLogging {
		c.Encoding = "console"
	}
	// are we running verbose mode?
	if config.Verbose {
		httplog.SetOutput(os.Stderr)
		c.DisableCaller = false
		c.Development = true
		c.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	return c.Build()
}

// createReverseProxy creates a reverse proxy
func (r *oauthProxy) createReverseProxy() error {
	r.log.Info("enabled reverse proxy mode, upstream url", zap.String("url", r.config.Upstream))
	if err := r.createUpstreamProxy(r.endpoint); err != nil {
		return err
	}
	engine := chi.NewRouter()
	engine.MethodNotAllowed(emptyHandler)
	engine.NotFound(emptyHandler)
	engine.Use(middleware.Recoverer)
	engine.Use(entrypointMiddleware)

	if r.config.EnableLogging {
		engine.Use(r.loggingMiddleware)
	}
	if r.config.EnableMetrics {
		engine.Use(r.metricsMiddleware)
	}
	if r.config.EnableSecurityFilter {
		engine.Use(r.securityMiddleware)
	}

	if len(r.config.CorsOrigins) > 0 {
		c := cors.New(cors.Options{
			AllowedOrigins:   r.config.CorsOrigins,
			AllowedMethods:   r.config.CorsMethods,
			AllowedHeaders:   r.config.CorsHeaders,
			AllowCredentials: r.config.CorsCredentials,
			ExposedHeaders:   r.config.CorsExposedHeaders,
			MaxAge:           int(r.config.CorsMaxAge.Seconds()),
		})
		engine.Use(c.Handler)
	}

	engine.Use(r.proxyMiddleware)
	r.router = engine

	// step: add the routing for oauth
	engine.With(proxyDenyMiddleware).Route(constants.OauthURL, func(e chi.Router) {
		e.MethodNotAllowed(methodNotAllowHandlder)
		e.Get(constants.AuthorizationURL, r.oauthAuthorizationHandler)
		e.Get(constants.CallbackURL, r.oauthCallbackHandler)
		e.Get(constants.ExpiredURL, r.expirationHandler)
		e.Get(constants.HealthURL, r.healthHandler)
		e.Get(constants.LogoutURL, r.logoutHandler)
		e.Get(constants.TokenURL, r.tokenHandler)
		e.Post(constants.LoginURL, r.loginHandler)
		if r.config.EnableMetrics {
			e.Get(constants.MetricsURL, r.proxyMetricsHandler)
		}
	})

	if r.config.EnableProfiling {
		engine.With(proxyDenyMiddleware).Route(constants.DebugURL, func(e chi.Router) {
			r.log.Warn("enabling the debug profiling on /debug/pprof")
			e.Get("/{name}", r.debugHandler)
			e.Post("/{name}", r.debugHandler)
		})
	}

	// step: load the templates if any
	if err := r.createTemplates(); err != nil {
		return err
	}
	// step: provision in the protected resources
	for _, x := range r.config.Resources {
		if x.URI[len(x.URI)-1:] == "/" {
			r.log.Warn("the resource url is not a prefix",
				zap.String("resource", x.URI),
				zap.String("change", x.URI),
				zap.String("ammended", strings.TrimRight(x.URI, "/")))
		}
	}

	for _, x := range r.config.Resources {
		r.log.Info("protecting resource", zap.String("resource", x.String()))
		e := engine.With(
			r.authenticationMiddleware(x),
			r.admissionMiddleware(x),
			r.headersMiddleware(r.config.AddClaims))

		for _, m := range x.Methods {
			if !x.WhiteListed {
				e.MethodFunc(m, x.URI, emptyHandler)
				continue
			}
			engine.MethodFunc(m, x.URI, emptyHandler)
		}
	}

	for name, value := range r.config.MatchClaims {
		r.log.Info("token must contain", zap.String("claim", name), zap.String("value", value))
	}
	if r.config.RedirectionURL == "" {
		r.log.Warn("no redirection url has been set, will use host headers")
	}
	if r.config.EnableEncryptedToken {
		r.log.Info("session access tokens will be encrypted")
	}
	if r.config.Upstream == "" && (r.config.EnableAuthorizationHeader || r.config.EnableTokenHeader) {
		r.log.Warn("no upstream has been configured, hence acting as an open reverse proxy, you sure you want tokens proxied")
	}

	return nil
}

// createForwardingProxy creates a forwarding proxy
func (r *oauthProxy) createForwardingProxy() error {
	r.log.Info("enabling forward signing mode, listening on", zap.String("interface", r.config.Listen))

	if r.config.SkipUpstreamTLSVerify {
		r.log.Warn("tls verification switched off. In forward signing mode it's recommended you verify! (--skip-upstream-tls-verify=false)")
	}
	if err := r.createUpstreamProxy(nil); err != nil {
		return err
	}
	forwardingHandler := r.forwardProxyHandler()

	// set the http handler
	proxy := r.upstream.(*goproxy.ProxyHttpServer)
	r.router = proxy

	// setup the tls configuration
	if r.config.TLSCaCertificate != "" && r.config.TLSCaPrivateKey != "" {
		ca, err := utils.LoadCA(r.config.TLSCaCertificate, r.config.TLSCaPrivateKey)
		if err != nil {
			return fmt.Errorf("unable to load certificate authority, error: %s", err)
		}

		// implement the goproxy connect method
		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return &goproxy.ConnectAction{
					Action:    goproxy.ConnectMitm,
					TLSConfig: goproxy.TLSConfigFromCA(ca),
				}, host
			},
		)
	} else {
		// use the default certificate provided by goproxy
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	}

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// @NOTES, somewhat annoying but goproxy hands back a nil response on proxy client errors
		if resp != nil && r.config.EnableLogging {
			start := ctx.UserData.(time.Time)
			latency := time.Since(start)
			r.log.Info("client request",
				zap.String("method", resp.Request.Method),
				zap.String("path", resp.Request.URL.Path),
				zap.Int("status", resp.StatusCode),
				zap.Int64("bytes", resp.ContentLength),
				zap.String("host", resp.Request.Host),
				zap.String("path", resp.Request.URL.Path),
				zap.String("latency", latency.String()))
		}

		return resp
	})
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.UserData = time.Now()
		forwardingHandler(req, ctx.Resp)
		return req, ctx.Resp
	})

	return nil
}

// Run starts the proxy service
func (r *oauthProxy) Run() error {
	listener, err := r.createHTTPListener(listenerConfig{
		listen:              r.config.Listen,
		certificate:         r.config.TLSCertificate,
		privateKey:          r.config.TLSPrivateKey,
		ca:                  r.config.TLSCaCertificate,
		clientCert:          r.config.TLSClientCertificate,
		proxyProtocol:       r.config.EnableProxyProtocol,
		useLetsEncrypt:      r.config.UseLetsEncrypt,
		letsEncryptCacheDir: r.config.LetsEncryptCacheDir,
		hostnames:           r.config.Hostnames,
		redirectionURL:      r.config.RedirectionURL,
	})
	if err != nil {
		return err
	}
	// step: create the http server
	server := &http.Server{
		Addr:         r.config.Listen,
		Handler:      r.router,
		ReadTimeout:  r.config.ServerReadTimeout,
		WriteTimeout: r.config.ServerWriteTimeout,
		IdleTimeout:  r.config.ServerIdleTimeout,
	}
	r.server = server
	r.listener = listener

	go func() {
		r.log.Info("keycloak proxy service starting", zap.String("interface", r.config.Listen))
		if err = server.Serve(listener); err != nil {
			if err != http.ErrServerClosed {
				r.log.Fatal("failed to start the http service", zap.Error(err))
			}
		}
	}()

	// step: are we running http service as well?
	if r.config.ListenHTTP != "" {
		r.log.Info("keycloak proxy http service starting", zap.String("interface", r.config.ListenHTTP))
		httpListener, err := r.createHTTPListener(listenerConfig{
			listen:        r.config.ListenHTTP,
			proxyProtocol: r.config.EnableProxyProtocol,
		})
		if err != nil {
			return err
		}
		httpsvc := &http.Server{
			Addr:         r.config.ListenHTTP,
			Handler:      r.router,
			ReadTimeout:  r.config.ServerReadTimeout,
			WriteTimeout: r.config.ServerWriteTimeout,
			IdleTimeout:  r.config.ServerIdleTimeout,
		}
		go func() {
			if err := httpsvc.Serve(httpListener); err != nil {
				r.log.Fatal("failed to start the http redirect service", zap.Error(err))
			}
		}()
	}

	return nil
}

// listenerConfig encapsulate listener options
type listenerConfig struct {
	ca                  string   // the path to a certificate authority
	certificate         string   // the path to the certificate if any
	clientCert          string   // the path to a client certificate to use for mutual tls
	hostnames           []string // list of hostnames the service will respond to
	letsEncryptCacheDir string   // the path to cache letsencrypt certificates
	listen              string   // the interface to bind the listener to
	privateKey          string   // the path to the private key if any
	proxyProtocol       bool     // whether to enable proxy protocol on the listen
	redirectionURL      string   // url to redirect to
	useLetsEncrypt      bool     // whether to use lets encrypt for retrieving ssl certificates
}

// ErrHostNotConfigured indicates the hostname was not configured
var ErrHostNotConfigured = errors.New("acme/autocert: host not configured")

// createHTTPListener is responsible for creating a listening socket
func (r *oauthProxy) createHTTPListener(config listenerConfig) (net.Listener, error) {
	var listener net.Listener
	var err error

	// are we create a unix socket or tcp listener?
	if strings.HasPrefix(config.listen, "unix://") {
		socket := strings.Trim(config.listen, "unix://")
		if exists := utils.FileExists(socket); exists {
			if err = os.Remove(socket); err != nil {
				return nil, err
			}
		}
		r.log.Info("listening on unix socket", zap.String("interface", config.listen))
		if listener, err = net.Listen("unix", socket); err != nil {
			return nil, err
		}
	} else {
		if listener, err = net.Listen("tcp", config.listen); err != nil {
			return nil, err
		}
	}

	// does it require proxy protocol?
	if config.proxyProtocol {
		r.log.Info("enabling the proxy protocol on listener", zap.String("interface", config.listen))
		listener = &proxyproto.Listener{Listener: listener}
	}

	// the default get certificate methid when tls is enabled
	if config.useLetsEncrypt || config.certificate != "" {
		var getCert certs.Provider
		tlsConfig := &tls.Config{
			PreferServerCipherSuites: true,
		}

		if config.useLetsEncrypt {
			r.log.Info("enabling letsencrypt tls support")
			getCert, err = letsencrypt.New(r.config, r.log)
			if err != nil {
				return nil, err
			}
		} else if config.certificate != "" {
			r.log.Info("enabling tls support")
			getCert, err = rotate.New(r.config, r.log)
			if err != nil {
				return nil, err
			}
		}
		tlsConfig.GetCertificate = getCert.GetCertificate

		// are we doing mutual tls?
		if config.clientCert != "" {
			caCert, err := ioutil.ReadFile(config.clientCert)
			if err != nil {
				return nil, err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		listener = tls.NewListener(listener, tlsConfig)
	}

	return listener, nil
}

// createUpstreamProxy create a reverse http proxy from the upstream
func (r *oauthProxy) createUpstreamProxy(endpoint *url.URL) error {
	dialer := (&net.Dialer{
		KeepAlive: r.config.UpstreamKeepaliveTimeout,
		Timeout:   r.config.UpstreamTimeout,
	}).Dial

	// are we using a unix socket?
	if endpoint != nil && endpoint.Scheme == "unix" {
		r.log.Info("using unix socket for endpoint", zap.String("socket", fmt.Sprintf("%s%s", endpoint.Host, endpoint.Path)))

		socketPath := fmt.Sprintf("%s%s", endpoint.Host, endpoint.Path)
		dialer = func(network, address string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		}
		endpoint.Path = ""
		endpoint.Host = "domain-sock"
		endpoint.Scheme = "http"
	}

	// create the upstream tls configure
	tlsConfig := &tls.Config{InsecureSkipVerify: r.config.SkipUpstreamTLSVerify}

	// are we using a client certificate
	// @TODO provide a means of reload on the client certificate when it expires. I'm not sure if it's just a
	// case of update the http transport settings - Also we to place this go-routine?
	if r.config.TLSClientCertificate != "" {
		cert, err := ioutil.ReadFile(r.config.TLSClientCertificate)
		if err != nil {
			r.log.Error("unable to read client certificate", zap.String("path", r.config.TLSClientCertificate), zap.Error(err))
			return err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cert)
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	{
		// @check if we have a upstream ca to verify the upstream
		if r.config.UpstreamCA != "" {
			r.log.Info("loading the upstream ca", zap.String("path", r.config.UpstreamCA))
			ca, err := ioutil.ReadFile(r.config.UpstreamCA)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca)
			tlsConfig.RootCAs = pool
		}
	}

	// create the forwarding proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = httplog.New(ioutil.Discard, "", 0)
	r.upstream = proxy

	// create the http transport
	tp := &http.Transport{
		Dial:                  dialer,
		DisableKeepAlives:     !r.config.UpstreamKeepalives,
		ExpectContinueTimeout: r.config.UpstreamExpectContinueTimeout,
		ResponseHeaderTimeout: r.config.UpstreamResponseHeaderTimeout,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   r.config.UpstreamTLSHandshakeTimeout,
	}

	// update the tls configuration of the reverse proxy
	r.upstream.(*goproxy.ProxyHttpServer).Tr = tp

	return nil
}

// createTemplates loads the custom template
func (r *oauthProxy) createTemplates() error {
	var list []string

	if r.config.SignInPage != "" {
		r.log.Debug("loading the custom sign in page", zap.String("page", r.config.SignInPage))
		list = append(list, r.config.SignInPage)
	}

	if r.config.ForbiddenPage != "" {
		r.log.Debug("loading the custom sign forbidden page", zap.String("page", r.config.ForbiddenPage))
		list = append(list, r.config.ForbiddenPage)
	}

	if len(list) > 0 {
		r.log.Info("loading the custom templates", zap.String("templates", strings.Join(list, ",")))
		r.templates = template.Must(template.ParseFiles(list...))
	}

	return nil
}

// newOpenIDClient initializes the openID configuration, note: the redirection url is deliberately left blank
// in order to retrieve it from the host header on request
func (r *oauthProxy) newOpenIDClient() (*oidc.Client, oidc.ProviderConfig, *http.Client, error) {
	var err error
	var config oidc.ProviderConfig

	// step: fix up the url if required, the underlining lib will add the .well-known/openid-configuration to the discovery url for us.
	if strings.HasSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration") {
		r.config.DiscoveryURL = strings.TrimSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration")
	}

	// step: create a idp http client
	hc := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				if r.config.OpenIDProviderProxy != "" {
					idpProxyURL, err := url.Parse(r.config.OpenIDProviderProxy)
					if err != nil {
						r.log.Warn("invalid proxy address for open IDP provider proxy", zap.Error(err))
						return nil, nil
					}
					return idpProxyURL, nil
				}

				return nil, nil
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: r.config.SkipOpenIDProviderTLSVerify,
			},
		},
		Timeout: time.Second * 10,
	}

	// step: attempt to retrieve the provider configuration
	completeCh := make(chan bool)
	go func() {
		for {
			r.log.Info("attempting to retrieve configuration discovery url", zap.String("url", r.config.DiscoveryURL))
			if config, err = oidc.FetchProviderConfig(hc, r.config.DiscoveryURL); err == nil {
				break // break and complete
			}
			r.log.Warn("failed to get provider configuration from discovery", zap.Error(err))
			time.Sleep(time.Second * 3)
		}
		completeCh <- true
	}()
	// wait for timeout or successful retrieval
	select {
	case <-time.After(30 * time.Second):
		return nil, config, nil, errors.New("failed to retrieve the provider configuration from discovery url")
	case <-completeCh:
		r.log.Info("successfully retrieved openid configuration from the discovery")
	}

	client, err := oidc.NewClient(oidc.ClientConfig{
		Credentials: oidc.ClientCredentials{
			ID:     r.config.ClientID,
			Secret: r.config.ClientSecret,
		},
		HTTPClient:        hc,
		RedirectURL:       fmt.Sprintf("%s/oauth/callback", r.config.RedirectionURL),
		ProviderConfig:    config,
		Scope:             append(r.config.Scopes, oidc.DefaultScope...),
		SkipClientIDCheck: r.config.SkipClientID,
	})
	if err != nil {
		return nil, config, hc, err
	}
	// start the provider sync for key rotation
	client.SyncProviderConfig(r.config.DiscoveryURL)

	return client, config, hc, nil
}

// Render implements the echo Render interface
func (r *oauthProxy) Render(w io.Writer, name string, data interface{}) error {
	return r.templates.ExecuteTemplate(w, name, data)
}
