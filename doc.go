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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	release  = "v2.3.0"
	gitsha   = "no gitsha provided"
	compiled = "0"
	version  = ""
)

type contextKey int8

const (
	prog        = "louketo-proxy"
	author      = "Louketo"
	email       = "louketo@googlegroups.com"
	description = "is a proxy using the keycloak service for auth and authorization"

	authorizationHeader = "Authorization"
	authorizationType   = "Bearer"
	envPrefix           = "PROXY_"
	headerUpgrade       = "Upgrade"
	versionHeader       = "X-Auth-Proxy-Version"

	authorizationURL = "/authorize"
	callbackURL      = "/callback"
	expiredURL       = "/expired"
	healthURL        = "/health"
	loginURL         = "/login"
	logoutURL        = "/logout"
	metricsURL       = "/metrics"
	tokenURL         = "/token"
	debugURL         = "/debug/pprof"

	claimAudience       = "aud"
	claimPreferredName  = "preferred_username"
	claimRealmAccess    = "realm_access"
	claimResourceAccess = "resource_access"
	claimResourceRoles  = "roles"
	claimGroups         = "groups"

	accessCookie       = "kc-access"
	refreshCookie      = "kc-state"
	requestURICookie   = "request_uri"
	requestStateCookie = "OAuth_Token_Request_State"
	unsecureScheme     = "http"
	secureScheme       = "https"
	anyMethod          = "ANY"
	authMethodBasic    = "secret-basic"
	authMethodBody     = "secret-body"

	_ contextKey = iota
	contextScopeName
)

const (
	headerXForwardedFor = "X-Forwarded-For"
	headerXRealIP       = "X-Real-IP"
)

var (
	certificateRotationMetric = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_certificate_rotation_total",
			Help: "The total amount of times the certificate has been rotated",
		},
	)
	oauthTokensMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_oauth_tokens_total",
			Help: "A summary of the tokens issuesd, renewed or failed logins",
		},
		[]string{"action"},
	)
	oauthLatencyMetric = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "proxy_oauth_request_latency_sec",
			Help: "A summary of the request latancy for requests against the openid provider",
		},
		[]string{"action"},
	)
	latencyMetric = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "proxy_request_duration_sec",
			Help: "A summary of the http request latency for proxy requests",
		},
	)
	statusMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_request_status_total",
			Help: "The HTTP requests partitioned by status code",
		},
		[]string{"code", "method"},
	)
)

var (
	// ErrSessionNotFound no session found in the request
	ErrSessionNotFound = errors.New("authentication session not found")
	// ErrNoSessionStateFound means there was not persist state
	ErrNoSessionStateFound = errors.New("no session state found")
	// ErrInvalidSession the session is invalid
	ErrInvalidSession = errors.New("invalid session identifier")
	// ErrAccessTokenExpired indicates the access token has expired
	ErrAccessTokenExpired = errors.New("the access token has expired")
	// ErrRefreshTokenExpired indicates the refresh token as expired
	ErrRefreshTokenExpired = errors.New("the refresh token has expired")
	// ErrNoTokenAudience indicates their is not audience in the token
	ErrNoTokenAudience = errors.New("the token does not audience in claims")
	// ErrDecryption indicates we can't decrypt the token
	ErrDecryption = errors.New("failed to decrypt token")
)

// Resource represents a url resource to protect
type Resource struct {
	// URL the url for the resource
	URL string `json:"uri" yaml:"uri"`
	// Methods the method type
	Methods []string `json:"methods" yaml:"methods"`
	// WhiteListed permits the prefix through
	WhiteListed bool `json:"white-listed" yaml:"white-listed"`
	// RequireAnyRole indicates that ANY of the roles are required, the default is all
	RequireAnyRole bool `json:"require-any-role" yaml:"require-any-role"`
	// Roles the roles required to access this url
	Roles []string `json:"roles" yaml:"roles"`
	// Groups is a list of groups the user is in
	Groups []string `json:"groups" yaml:"groups"`
}

// Config is the configuration for the proxy
type Config struct {
	// ConfigFile is the binding interface
	ConfigFile string `json:"config" yaml:"config" usage:"path the a configuration file" env:"CONFIG_FILE"`
	// Listen is the binding interface
	Listen string `json:"listen" yaml:"listen" usage:"the interface the service should be listening on" env:"LISTEN"`
	// ListenHTTP is the interface to bind the http only service on
	ListenHTTP string `json:"listen-http" yaml:"listen-http" usage:"interface we should be listening" env:"LISTEN_HTTP"`
	// DiscoveryURL is the url for the keycloak server
	DiscoveryURL string `json:"discovery-url" yaml:"discovery-url" usage:"discovery url to retrieve the openid configuration" env:"DISCOVERY_URL"`
	// ClientID is the client id
	ClientID string `json:"client-id" yaml:"client-id" usage:"client id used to authenticate to the oauth service" env:"CLIENT_ID"`
	// ClientSecret is the secret for AS
	ClientSecret string `json:"client-secret" yaml:"client-secret" usage:"client secret used to authenticate to the oauth service" env:"CLIENT_SECRET"`
	// RedirectionURL the redirection url
	RedirectionURL string `json:"redirection-url" yaml:"redirection-url" usage:"redirection url for the oauth callback url, defaults to host header if absent" env:"REDIRECTION_URL"`
	// RevocationEndpoint is the token revocation endpoint to revoke refresh tokens
	RevocationEndpoint string `json:"revocation-url" yaml:"revocation-url" usage:"url for the revocation endpoint to revoke refresh token" env:"REVOCATION_URL"`
	// SkipOpenIDProviderTLSVerify skips the tls verification for openid provider communication
	SkipOpenIDProviderTLSVerify bool `json:"skip-openid-provider-tls-verify" yaml:"skip-openid-provider-tls-verify" usage:"skip the verification of any TLS communication with the openid provider"`
	// OpenIDProviderProxy proxy for openid provider communication
	OpenIDProviderProxy string `json:"openid-provider-proxy" yaml:"openid-provider-proxy" usage:"proxy for communication with the openid provider"`
	// OpenIDProviderTimeout is the timeout used to pulling the openid configuration from the provider
	OpenIDProviderTimeout time.Duration `json:"openid-provider-timeout" yaml:"openid-provider-timeout" usage:"timeout for openid configuration on .well-known/openid-configuration"`
	// BaseURI is prepended to all the generated URIs
	BaseURI string `json:"base-uri" yaml:"base-uri" usage:"common prefix for all URIs" env:"BASE_URI"`
	// OAuthURI is the uri for the oauth endpoints for the proxy
	OAuthURI string `json:"oauth-uri" yaml:"oauth-uri" usage:"the uri for proxy oauth endpoints" env:"OAUTH_URI"`
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" yaml:"scopes" usage:"list of scopes requested when authenticating the user"`
	// Upstream is the upstream endpoint i.e whom were proxying to
	Upstream string `json:"upstream-url" yaml:"upstream-url" usage:"url for the upstream endpoint you wish to proxy" env:"UPSTREAM_URL"`
	// UpstreamCA is the path to a CA certificate in PEM format to validate the upstream certificate
	UpstreamCA string `json:"upstream-ca" yaml:"upstream-ca" usage:"the path to a file container a CA certificate to validate the upstream tls endpoint"`
	// Resources is a list of protected resources
	Resources []*Resource `json:"resources" yaml:"resources" usage:"list of resources 'uri=/admin*|methods=GET,PUT|roles=role1,role2'"`
	// Headers permits adding customs headers across the board
	Headers map[string]string `json:"headers" yaml:"headers" usage:"custom headers to the upstream request, key=value"`
	// PreserveHost preserves the host header of the proxied request in the upstream request
	PreserveHost bool `json:"preserve-host" yaml:"preserve-host" usage:"preserve the host header of the proxied request in the upstream request"`
	// RequestIDHeader is the header name for request ids
	RequestIDHeader string `json:"request-id-header" yaml:"request-id-header" usage:"the http header name for request id" env:"REQUEST_ID_HEADER"`
	// ResponseHeader is a map of response headers to add to the response
	ResponseHeaders map[string]string `json:"response-headers" yaml:"response-headers" usage:"custom headers to added to the http response key=value"`

	// EnableSelfSignedTLS indicates we should create a self-signed ceritificate for the service
	EnabledSelfSignedTLS bool `json:"enable-self-signed-tls" yaml:"enable-self-signed-tls" usage:"create self signed certificates for the proxy" env:"ENABLE_SELF_SIGNED_TLS"`
	// SelfSignedTLSHostnames is the list of hostnames to place on the certificate
	SelfSignedTLSHostnames []string `json:"self-signed-tls-hostnames" yaml:"self-signed-tls-hostnames" usage:"a list of hostnames to place on the self-signed certificate"`
	// SelfSignedTLSExpiration is the expiration time of the tls certificate before rotation occurs
	SelfSignedTLSExpiration time.Duration `json:"self-signed-tls-expiration" yaml:"self-signed-tls-expiration" usage:"the expiration of the certificate before rotation"`

	// EnableRequestID indicates the proxy should add request id if none if found
	EnableRequestID bool `json:"enable-request-id" yaml:"enable-request-id" usage:"indicates we should add a request id if none found" env:"ENABLE_REQUEST_ID"`
	// EnableLogoutRedirect indicates we should redirect to the identity provider for logging out
	EnableLogoutRedirect bool `json:"enable-logout-redirect" yaml:"enable-logout-redirect" usage:"indicates we should redirect to the identity provider for logging out"`
	// EnableDefaultDeny indicates we should deny by default all requests
	EnableDefaultDeny bool `json:"enable-default-deny" yaml:"enable-default-deny" usage:"enables a default denial on all requests, you have to explicitly say what is permitted (recommended)"`
	// EnableEncryptedToken indicates the access token should be encoded
	EnableEncryptedToken bool `json:"enable-encrypted-token" yaml:"enable-encrypted-token" usage:"enable encryption for the access tokens"`
	// ForceEncryptedCookie indicates that the access token in the cookie should be encoded, regardless what EnableEncryptedToken says. This way, Louketo Proxy may receive tokens in header in the clear, whereas tokens in cookies remain encrypted
	ForceEncryptedCookie bool `json:"force-encrypted-cookie" yaml:"force-encrypted-cookie" usage:"force encryption for the access tokens in cookies"`
	// EnableLogging indicates if we should log all the requests
	EnableLogging bool `json:"enable-logging" yaml:"enable-logging" usage:"enable http logging of the requests"`
	// EnableJSONLogging is the logging format
	EnableJSONLogging bool `json:"enable-json-logging" yaml:"enable-json-logging" usage:"switch on json logging rather than text"`
	// EnableForwarding enables the forwarding proxy
	EnableForwarding bool `json:"enable-forwarding" yaml:"enable-forwarding" usage:"enables the forwarding proxy mode, signing outbound request"`
	// EnableSecurityFilter enabled the security handler
	EnableSecurityFilter bool `json:"enable-security-filter" yaml:"enable-security-filter" usage:"enables the security filter handler" env:"ENABLE_SECURITY_FILTER"`
	// EnableRefreshTokens indicate's you wish to ignore using refresh tokens and re-auth on expiration of access token
	EnableRefreshTokens bool `json:"enable-refresh-tokens" yaml:"enable-refresh-tokens" usage:"enables the handling of the refresh tokens" env:"ENABLE_REFRESH_TOKEN"`
	// EnableSessionCookies indicates the cookies, both token and refresh should not be persisted
	EnableSessionCookies bool `json:"enable-session-cookies" yaml:"enable-session-cookies" usage:"access and refresh tokens are session only i.e. removed browser close"`
	// EnableLoginHandler indicates we want the login handler enabled
	EnableLoginHandler bool `json:"enable-login-handler" yaml:"enable-login-handler" usage:"enables the handling of the refresh tokens" env:"ENABLE_LOGIN_HANDLER"`
	// EnableTokenHeader adds the JWT token to the upstream authentication headers
	EnableTokenHeader bool `json:"enable-token-header" yaml:"enable-token-header" usage:"enables the token authentication header X-Auth-Token to upstream"`
	// EnableAuthorizationHeader indicates we should pass the authorization header to the upstream endpoint
	EnableAuthorizationHeader bool `json:"enable-authorization-header" yaml:"enable-authorization-header" usage:"adds the authorization header to the proxy request" env:"ENABLE_AUTHORIZATION_HEADER"`
	// EnableAuthorizationCookies indicates we should pass the authorization cookies to the upstream endpoint
	EnableAuthorizationCookies bool `json:"enable-authorization-cookies" yaml:"enable-authorization-cookies" usage:"adds the authorization cookies to the uptream proxy request" env:"ENABLE_AUTHORIZATION_COOKIES"`
	// EnableHTTPSRedirect indicate we should redirection http -> https
	EnableHTTPSRedirect bool `json:"enable-https-redirection" yaml:"enable-https-redirection" usage:"enable the http to https redirection on the http service"`
	// EnableProfiling indicates if profiles is switched on
	EnableProfiling bool `json:"enable-profiling" yaml:"enable-profiling" usage:"switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc"`
	// EnableMetrics indicates if the metrics is enabled
	EnableMetrics bool `json:"enable-metrics" yaml:"enable-metrics" usage:"enable the prometheus metrics collector on /oauth/metrics"`
	// EnableBrowserXSSFilter indicates you want the filter on
	EnableBrowserXSSFilter bool `json:"filter-browser-xss" yaml:"filter-browser-xss" usage:"enable the adds the X-XSS-Protection header with mode=block"`
	// EnableContentNoSniff indicates you want the filter on
	EnableContentNoSniff bool `json:"filter-content-nosniff" yaml:"filter-content-nosniff" usage:"adds the X-Content-Type-Options header with the value nosniff"`
	// EnableFrameDeny indicates the filter is on
	EnableFrameDeny bool `json:"filter-frame-deny" yaml:"filter-frame-deny" usage:"enable to the frame deny header"`
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value
	ContentSecurityPolicy string `json:"content-security-policy" yaml:"content-security-policy" usage:"specify the content security policy"`
	// LocalhostMetrics indicated the metrics can only be consume via localhost
	LocalhostMetrics bool `json:"localhost-metrics" yaml:"localhost-metrics" usage:"enforces the metrics page can only been requested from 127.0.0.1"`
	// EnableCompression enables gzip compression for response
	EnableCompression bool `json:"enable-compression" yaml:"enable-compression" usage:"enable gzip compression for response"`
	// EnableCSRFCheck enables CSRF protection between authorise/callback using cookies and state parameter
	EnableCSRFCheck bool `json:"enable-csrf-check" yaml:"enable-csrf-check" usage:"enable crsf check between authorise and callback"`

	// AccessTokenDuration is default duration applied to the access token cookie
	AccessTokenDuration time.Duration `json:"access-token-duration" yaml:"access-token-duration" usage:"fallback cookie duration for the access token when using refresh tokens"`
	// ClientAuthMethod defines the method for authenticating the oauth client to the server
	ClientAuthMethod string `json:"client-auth-method" yaml:"client-auth-method" usage:"the auth method to use with oauth (secret-basic, secret-body)" env:"CLIENT_AUTH_METHOD"`
	// CookieDomain is a list of domains the cookie is available to
	CookieDomain string `json:"cookie-domain" yaml:"cookie-domain" usage:"domain the access cookie is available to, defaults host header"`
	// CookieAccessName is the name of the access cookie holding the access token
	CookieAccessName string `json:"cookie-access-name" yaml:"cookie-access-name" usage:"name of the cookie use to hold the access token"`
	// CookieRefreshName is the name of the refresh cookie
	CookieRefreshName string `json:"cookie-refresh-name" yaml:"cookie-refresh-name" usage:"name of the cookie used to hold the encrypted refresh token"`
	// SecureCookie enforces the cookie as secure
	SecureCookie bool `json:"secure-cookie" yaml:"secure-cookie" usage:"enforces the cookie to be secure"`
	// HTTPOnlyCookie enforces the cookie as http only
	HTTPOnlyCookie bool `json:"http-only-cookie" yaml:"http-only-cookie" usage:"enforces the cookie is in http only mode"`
	// SameSiteCookie enforces cookies to be send only to same site requests.
	SameSiteCookie string `json:"same-site-cookie" yaml:"same-site-cookie" usage:"enforces cookies to be send only to same site requests according to the policy (can be Strict|Lax|None)"`

	// MatchClaims is a series of checks, the claims in the token must match those here
	MatchClaims map[string]string `json:"match-claims" yaml:"match-claims" usage:"keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*"`
	// AddClaims is a series of claims that should be added to the auth headers
	AddClaims []string `json:"add-claims" yaml:"add-claims" usage:"extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name"`

	// TLSCertificate is the location for a tls certificate
	TLSCertificate string `json:"tls-cert" yaml:"tls-cert" usage:"path to ths TLS certificate"`
	// TLSPrivateKey is the location of a tls private key
	TLSPrivateKey string `json:"tls-private-key" yaml:"tls-private-key" usage:"path to the private key for TLS"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSCaCertificate string `json:"tls-ca-certificate" yaml:"tls-ca-certificate" usage:"path to the ca certificate used for signing requests"`
	// TLSCaPrivateKey is the CA private key used for signing
	TLSCaPrivateKey string `json:"tls-ca-key" yaml:"tls-ca-key" usage:"path the ca private key, used by the forward signing proxy"`
	// TLSClientCertificate is path to a client certificate to use for outbound connections
	TLSClientCertificate string `json:"tls-client-certificate" yaml:"tls-client-certificate" usage:"path to the client certificate for outbound connections in reverse and forwarding proxy modes"`
	// SkipUpstreamTLSVerify skips the verification of any upstream tls
	SkipUpstreamTLSVerify bool `json:"skip-upstream-tls-verify" yaml:"skip-upstream-tls-verify" usage:"skip the verification of any upstream TLS"`

	// CorsOrigins is a list of origins permitted
	CorsOrigins []string `json:"cors-origins" yaml:"cors-origins" usage:"origins to add to the CORE origins control (Access-Control-Allow-Origin)"`
	// CorsMethods is a set of access control methods
	CorsMethods []string `json:"cors-methods" yaml:"cors-methods" usage:"methods permitted in the access control (Access-Control-Allow-Methods)"`
	// CorsHeaders is a set of cors headers
	CorsHeaders []string `json:"cors-headers" yaml:"cors-headers" usage:"set of headers to add to the CORS access control (Access-Control-Allow-Headers)"`
	// CorsExposedHeaders are the exposed header fields
	CorsExposedHeaders []string `json:"cors-exposed-headers" yaml:"cors-exposed-headers" usage:"expose cors headers access control (Access-Control-Expose-Headers)"`
	// CorsCredentials set the credentials flag
	CorsCredentials bool `json:"cors-credentials" yaml:"cors-credentials" usage:"credentials access control header (Access-Control-Allow-Credentials)"`
	// CorsMaxAge is the age for CORS
	CorsMaxAge time.Duration `json:"cors-max-age" yaml:"cors-max-age" usage:"max age applied to cors headers (Access-Control-Max-Age)"`
	// Hostnames is a list of hostname's the service should response to
	Hostnames []string `json:"hostnames" yaml:"hostnames" usage:"list of hostnames the service will respond to"`

	// Store is a url for a store resource, used to hold the refresh tokens
	StoreURL string `json:"store-url" yaml:"store-url" usage:"url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption-key" yaml:"encryption-key" usage:"encryption key used to encryption the session state" env:"ENCRYPTION_KEY"`

	// NoRedirects informs we should hand back a 401 not a redirect
	NoRedirects bool `json:"no-redirects" yaml:"no-redirects" usage:"do not have back redirects when no authentication is present, 401 them"`
	// SkipTokenVerification tells the service to skipp verifying the access token - for testing purposes
	SkipTokenVerification bool `json:"skip-token-verification" yaml:"skip-token-verification" usage:"TESTING ONLY; bypass token verification, only expiration and roles enforced"`
	// UpstreamKeepalives specifies whether we use keepalives on the upstream
	UpstreamKeepalives bool `json:"upstream-keepalives" yaml:"upstream-keepalives" usage:"enables or disables the keepalive connections for upstream endpoint"`
	// UpstreamTimeout is the maximum amount of time a dial will wait for a connect to complete
	UpstreamTimeout time.Duration `json:"upstream-timeout" yaml:"upstream-timeout" usage:"maximum amount of time a dial will wait for a connect to complete"`
	// UpstreamKeepaliveTimeout is the upstream keepalive timeout
	UpstreamKeepaliveTimeout time.Duration `json:"upstream-keepalive-timeout" yaml:"upstream-keepalive-timeout" usage:"specifies the keep-alive period for an active network connection"`
	// UpstreamTLSHandshakeTimeout is the timeout for upstream to tls handshake
	UpstreamTLSHandshakeTimeout time.Duration `json:"upstream-tls-handshake-timeout" yaml:"upstream-tls-handshake-timeout" usage:"the timeout placed on the tls handshake for upstream"`
	// UpstreamResponseHeaderTimeout is the timeout for upstream header response
	UpstreamResponseHeaderTimeout time.Duration `json:"upstream-response-header-timeout" yaml:"upstream-response-header-timeout" usage:"the timeout placed on the response header for upstream"`
	// UpstreamExpectContinueTimeout is the timeout expect continue for upstream
	UpstreamExpectContinueTimeout time.Duration `json:"upstream-expect-continue-timeout" yaml:"upstream-expect-continue-timeout" usage:"the timeout placed on the expect continue for upstream"`

	// Verbose switches on debug logging
	Verbose bool `json:"verbose" yaml:"verbose" usage:"switch on debug / verbose logging"`
	// EnableProxyProtocol controls the proxy protocol
	EnableProxyProtocol bool `json:"enabled-proxy-protocol" yaml:"enabled-proxy-protocol" usage:"enable proxy protocol"`

	// MaxIdleConns is the max idle connections to keep alive, ready for reuse
	MaxIdleConns int `json:"max-idle-connections" yaml:"max-idle-connections" usage:"max idle upstream / keycloak connections to keep alive, ready for reuse"`
	// MaxIdleConnsPerHost limits the number of idle connections maintained per host
	MaxIdleConnsPerHost int `json:"max-idle-connections-per-host" yaml:"max-idle-connections-per-host" usage:"limits the number of idle connections maintained per host"`

	// ServerReadTimeout is the read timeout on the http server
	ServerReadTimeout time.Duration `json:"server-read-timeout" yaml:"server-read-timeout" usage:"the server read timeout on the http server"`
	// ServerWriteTimeout is the write timeout on the http server
	ServerWriteTimeout time.Duration `json:"server-write-timeout" yaml:"server-write-timeout" usage:"the server write timeout on the http server"`
	// ServerIdleTimeout is the idle timeout on the http server
	ServerIdleTimeout time.Duration `json:"server-idle-timeout" yaml:"server-idle-timeout" usage:"the server idle timeout on the http server"`

	// UseLetsEncrypt controls if we should use letsencrypt to retrieve certificates
	UseLetsEncrypt bool `json:"use-letsencrypt" yaml:"use-letsencrypt" usage:"use letsencrypt for certificates"`

	// LetsEncryptCacheDir is the path to store letsencrypt certificates
	LetsEncryptCacheDir string `json:"letsencrypt-cache-dir" yaml:"letsencrypt-cache-dir" usage:"path where cached letsencrypt certificates are stored"`

	// SignInPage is the relative url for the sign in page
	SignInPage string `json:"sign-in-page" yaml:"sign-in-page" usage:"path to custom template displayed for signin"`
	// ForbiddenPage is a access forbidden page
	ForbiddenPage string `json:"forbidden-page" yaml:"forbidden-page" usage:"path to custom template used for access forbidden"`
	// Tags is passed to the templates
	Tags map[string]string `json:"tags" yaml:"tags" usage:"keypairs passed to the templates at render,e.g title=Page"`

	// ForwardingUsername is the username to login to the oauth service
	ForwardingUsername string `json:"forwarding-username" yaml:"forwarding-username" usage:"username to use when logging into the openid provider" env:"FORWARDING_USERNAME"`
	// ForwardingPassword is the password to use for the above
	ForwardingPassword string `json:"forwarding-password" yaml:"forwarding-password" usage:"password to use when logging into the openid provider" env:"FORWARDING_PASSWORD"`
	// ForwardingDomains is a collection of domains to signs
	ForwardingDomains []string `json:"forwarding-domains" yaml:"forwarding-domains" usage:"list of domains which should be signed; everything else is relayed unsigned"`

	// DisableAllLogging indicates no logging at all
	DisableAllLogging bool `json:"disable-all-logging" yaml:"disable-all-logging" usage:"disables all logging to stdout and stderr"`
}

// getVersion returns the proxy version
func getVersion() string {
	if version == "" {
		tm, err := strconv.ParseInt(compiled, 10, 64)
		if err != nil {
			return "unable to parse compiled time"
		}
		version = fmt.Sprintf("%s (git+sha: %s, built: %s)", release, gitsha, time.Unix(tm, 0).Format("02-01-2006"))
	}

	return version
}

// RequestScope is a request level context scope passed between middleware
type RequestScope struct {
	// AccessDenied indicates the request should not be proxied on
	AccessDenied bool
	// Identity is the user Identity of the request
	Identity *userContext
	// The parsed (unescaped) value of the request path
	Path string
	// Preserve the original request path: KEYCLOAK-10864, KEYCLOAK-11276, KEYCLOAK-13315
	// The exact path received in the request, if different than Path
	RawPath string
}

// storage is used to hold the offline refresh token, assuming you don't want to use
// the default practice of a encrypted cookie
type storage interface {
	// Set the token to the store
	Set(string, string, time.Duration) error
	// Get retrieves a token from the store
	Get(string) (string, error)
	// Delete removes a key from the store
	Delete(string) error
	// Close is used to close off any resources
	Close() error
}

// reverseProxy is a wrapper
type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

// userContext holds the information extracted the token
type userContext struct {
	// the id of the user
	id string
	// the audience for the token
	audiences []string
	// whether the context is from a session cookie or authorization header
	bearerToken bool
	// the claims associated to the token
	claims jose.Claims
	// the email associated to the user
	email string
	// the expiration of the access token
	expiresAt time.Time
	// groups is a collection of groups the user in in
	groups []string
	// a name of the user
	name string
	// preferredName is the name of the user
	preferredName string
	// roles is a collection of roles the users holds
	roles []string
	// the access token itself
	token jose.JWT
}

// tokenResponse
type tokenResponse struct {
	TokenType    string  `json:"token_type"`
	AccessToken  string  `json:"access_token"`
	IDToken      string  `json:"id_token"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	ExpiresIn    float64 `json:"expires_in"`
	Scope        string  `json:"scope,omitempty"`
}
