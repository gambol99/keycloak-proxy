[![Build Status](https://travis-ci.org/gambol99/keycloak-proxy.svg?branch=master)](https://travis-ci.org/gambol99/keycloak-proxy)
[![GoDoc](http://godoc.org/github.com/gambol99/keycloak-proxy?status.png)](http://godoc.org/github.com/gambol99/keycloak-proxy)
[![Docker Repository on Quay](https://quay.io/repository/gambol99/keycloak-proxy/status "Docker Repository on Quay")](https://quay.io/repository/gambol99/keycloak-proxy)

### **Keycloak Proxy**
----

  - Supports role based uri controls
  - Websocket connection upgrading
  - Token claim matching for additional ACL controls
  - Custom claim injections into authenticated requests
  - Stateless offline refresh tokens with optional predefined session limits
  - TLS and mutual TLS support
  - JSON field bases access logs
  - Custom Sign-in and access forbidden pages

----

Keycloak-proxy is a proxy service which at the risk of stating the obvious integrates with the [Keycloak](https://github.com/keycloak/keycloak) authentication service. Although technically the service has no dependency on Keycloak itself and would quite happily work with any OpenID provider. The service supports both access tokens in browser cookie or bearer tokens.

```shell
[jest@starfury keycloak-proxy]$ bin/keycloak-proxy help
NAME:
   keycloak-proxy - is a proxy using the keycloak service for auth and authorization

USAGE:
   keycloak-proxy [global options] command [command options] [arguments...]

VERSION:
   v1.0.5

AUTHOR(S):
   Rohith <gambol99@gmail.com>

COMMANDS:
GLOBAL OPTIONS:
   --config                                     the path to the configuration file for the keycloak proxy
   --listen "127.0.0.1:3000"                    the interface the service should be listening on
   --client-secret                              the client secret used to authenticate to the oauth server
   --client-id                                  the client id used to authenticate to the oauth serves
   --discovery-url                              the discovery url to retrieve the openid configuration
   --scope [--scope option --scope option]      a variable list of scopes requested when authenticating the user
   --idle-duration "0"                          the expiration of the access token cookie, if not used within this time its removed
   --redirection-url                            redirection url for the oauth callback url (/oauth is added)
   --upstream-url "http://127.0.0.1:8081"       the url for the upstream endpoint you wish to proxy to
   --revocation-url "/oauth2/revoke"            the url for the revocation endpoint to revoke refresh token
   --store-url                                  url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file
   --upstream-keepalives                        enables or disables the keepalive connections for upstream endpoint
   --enable-refresh-tokens                      enables the handling of the refresh tokens
   --secure-cookie                              enforces the cookie to be secure, default to true
   --cookie-access-name "kc-access"             the name of the cookie use to hold the access token
   --cookie-refresh-name "kc-state"             the name of the cookie used to hold the encrypted refresh token
   --encryption-key                             the encryption key used to encrpytion the session state
   --no-redirects                               do not have back redirects when no authentication is present, 401 them
   --hostname [--hostname option --hostname option]   a list of hostnames the service will respond to, defaults to all
   --tls-cert                                   the path to a certificate file used for TLS
   --tls-private-key                            the path to the private key for TLS support
   --tls-ca-certificate                         the path to the ca certificate used for mutual TLS
   --skip-upstream-tls-verify                   whether to skip the verification of any upstream TLS (defaults to true)
   --match-claims [--match-claims option --match-claims option]   keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*
   --add-claims [--add-claims option --add-claims option]         retrieve extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name
   --resource [--resource option --resource option]               a list of resources 'uri=/admin|methods=GET|roles=role1,role2'
   --signin-page                                a custom template displayed for signin
   --forbidden-page                             a custom template used for access forbidden
   --tag [--tag option --tag option]            keypair's passed to the templates at render,e.g title='My Page'
   --cors-origins [--cors-origins option --cors-origins option]   list of origins to add to the CORE origins control (Access-Control-Allow-Origin)
   --cors-methods [--cors-methods option --cors-methods option]   the method permitted in the access control (Access-Control-Allow-Methods)
   --cors-headers [--cors-headers option --cors-headers option]   a set of headers to add to the CORS access control (Access-Control-Allow-Headers)
   --cors-exposes-headers [--cors-exposes-headers option --cors-exposes-headers option]	set the expose cors headers access control (Access-Control-Expose-Headers)
   --cors-max-age "0"                           the max age applied to cors headers (Access-Control-Max-Age)
   --cors-credentials                           the credentials access control header (Access-Control-Allow-Credentials)
   --headers [--headers option --headers option]                  Add custom headers to the upstream request, key=value
   --enable-security-filter                     enables the security filter handler
   --skip-token-verification                    TESTING ONLY; bypass's token verification, expiration and roles enforced
   --offline-session                            enables the offline session of tokens via offline access (defaults false)
   --json-logging                               switch on json logging rather than text (defaults true)
   --log-requests                               switch on logging of all incoming requests (defaults true)
   --verbose                                    switch on debug / verbose logging
   --help, -h                                   show help
   --version, -v                                print the version

```

#### **Configuration**

The configuration can come from a yaml/json file and or the command line options (note, command options have a higher priority and will override any options referenced in a config file)

```YAML
# is the url for retrieve the openid configuration - normally the <server>/auth/realm/<realm_name>
discovery-url: https://keycloak.example.com/auth/realms/<REALM_NAME>
# the client id for the 'client' application
client-id: <CLIENT_ID>
# the secret associated to the 'client' application
client-secret: <CLIENT_SECRET>
# the interface definition you wish the proxy to listen, all interfaces is specified as ':<port>'
listen: 127.0.0.1:3000
# whether to enable refresh tokens
enable-refresh-token: true
# the location of a certificate you wish the proxy to use for TLS support
tls-cert:
# the location of a private key for TLS
tls-private-key:
# the redirection url, essentially the site url, note: /oauth/callback is added at the end
redirection-url: http://127.0.0.1:3000
# the encryption key used to encode the session state
encryption-key: <ENCRYPTION_KEY>
# the upstream endpoint which we should proxy request
upstream-url: http://127.0.0.1:80
# additional scopes to add to add to the default (openid+email+profile)
scopes:
  - vpn-user

# a collection of resource i.e. urls that you wish to protect
resources:
  - url: /admin/test
    # the methods on this url that should be protected, if missing, we assuming all
    methods:
      - GET
    # a list of roles the user must have in order to accces urls under the above
    roles:
      - openvpn:vpn-user
      - openvpn:prod-vpn
      - test
  - url: /admin
    methods:
      - GET
    roles:
      - openvpn:vpn-user
      - openvpn:commons-prod-vpn
```

#### **Example Usage**

Assuming you have some web service you wish protected by Keycloak;

a) Create the *client* under the Keycloak GUI or CLI; the client protocol is *'openid-connect'*, access-type:  *confidential*.
b) Add a Valid Redirect URIs of *http://127.0.0.1:3000/oauth/callback*.
c) Grab the client id and client secret.
d) Create the various roles under the client or existing clients for authorization purposes.

##### **- The default config**

```YAML
discovery-url: https://keycloak.example.com/auth/realms/<REALM_NAME>
client-id: <CLIENT_ID>
client-secret: <CLIENT_SECRET>
listen: 127.0.0.1:3000
redirection-url: http://127.0.0.1:3000
refresh_session: false
encryption_key: AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j
upstream-url: http://127.0.0.1:80

resources:
  - url: /admin
    methods:
      - GET
    roles:
      - client:test1
      - client:test2
  - url: /backend
    roles:
      - client:test1
```

Note, anything defined in the configuration file can also be configured as command line options, so the above would be reflected as;

```shell
bin/keycloak-proxy \
    --discovery-url=https://keycloak.example.com/auth/realms/<REALM_NAME> \
    --client-id=<CLIENT_ID> \
    --client-secret=<SECRET> \
    --listen=127.0.0.1:3000 \
    --redirection-url=http://127.0.0.1:3000 \
    --refresh-sessions=true \
    --encryption-key=AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j \
    --upstream-url=http://127.0.0.1:80 \
    --resource="uri=/admin|methods=GET|roles=test1,test2" \
    --resource="uri=/backend|roles=test1"
```

#### **- Google OAuth**
---
Although the role extensions do require a Keycloak IDP or at the very least a IDP that produces a token which contains roles, there's nothing stopping you from using it against any OpenID providers, such as Google. Go to the Google Developers Console and create a new application *(via "Enable and Manage APIs -> Credentials)*. Once you've created the application, take the client id, secret and make sure you've added the callback url to the application scope *(using the default this would be http://127.0.0.1:3000/oauth/callback)*

``` shell
bin/keycloak-proxy \
    --discovery-url=https://accounts.google.com/.well-known/openid-configuration \
    --client-id=<CLIENT_ID> \
    --client-secret=<CLIENT_SECRET> \
    --resource="uri=/" \   
    --verbose=true
```

Open a browser an go to http://127.0.0.1:3000 and you should be redirected to Google for authenticate and back the application when done and you should see something like the below.

```shell
DEBU[0002] resource access permitted: /                  access=permitted bearer=false expires=57m51.32029042s resource=/ username=gambol99@gmail.com
2016-02-06 13:59:01.680300 I | http: proxy error: dial tcp 127.0.0.1:8081: getsockopt: connection refused
DEBU[0002] resource access permitted: /favicon.ico       access=permitted bearer=false expires=57m51.144004098s resource=/ username=gambol99@gmail.com
2016-02-06 13:59:01.856716 I | http: proxy error: dial tcp 127.0.0.1:8081: getsockopt: connection refused
```
---
#### **- Upstream Headers**

On protected resources the upstream endpoint will receive a number of headers added by the proxy, along with an custom claims.

```GO
# add the header to the upstream endpoint
cx.Request.Header.Add("X-Auth-UserId", id.id)
cx.Request.Header.Add("X-Auth-Subject", id.preferredName)
cx.Request.Header.Add("X-Auth-Username", id.name)
cx.Request.Header.Add("X-Auth-Email", id.email)
cx.Request.Header.Add("X-Auth-ExpiresIn", id.expiresAt.String())
cx.Request.Header.Add("X-Auth-Token", id.token.Encode())
cx.Request.Header.Add("X-Auth-Roles", strings.Join(id.roles, ","))

# plus the default
cx.Request.Header.Add("X-Forwarded-For", <CLIENT_IP>)
cx.Request.Header.Add("X-Forwarded-Proto", <CLIENT_PROTO>)
```

#### **- Custom Claims**

You can inject additional claims from the access token into the authentication token via the --add-claims or config array. For example, the token from Keycloak provider
might include the following claims.

```YAML
"resource_access": {},
"name": "Rohith Jayawardene",
"preferred_username": "rohith.jayawardene",
"given_name": "Rohith",
"family_name": "Jayawardene",
"email": "gambol99@gmail.com"
```

In order to request you receive the given_name, family_name and name we could add --add-claims=given_name --add-claims=family_name etc. Or in the configuration file

```YAML
add-claims:
- given_name
- family_name
- name
```

Which would add the following headers to the authenticated request

```shell
X-Auth-Email: gambol99@gmail.com
X-Auth-Expiresin: 2016-05-03 22:27:43 +0000 UTC
X-Auth-Family-Name: Jayawardene
X-Auth-Given-Name: Rohith
X-Auth-Name: Rohith Jayawardene
X-Auth-Roles: test-role
X-Auth-Subject: rohith.jayawardene
```

#### **- Encryption Key**

In order to remain stateless and not have to rely on a central cache to persist the 'refresh_tokens', the refresh token is encrypted and added as a cookie using *crypto/aes*.
Naturally the key must be the same if your running behind a load balancer etc. The key length should either 16 or 32 bytes depending or whether you want AES-128 or AES-256.

#### **- Claim Matching**

The proxy supports adding a variable list of claim matches against the presented tokens for additional access control. So for example you can match the 'iss' or 'aud' to the token or custom attributes;
note each of the matches are regex's. Examples,  --match-claims 'aud=sso.*' --claim iss=https://.*' or via the configuratin file.

```YAML
match-claims:
  aud: openvpn
  iss: https://keycloak.example.com/auth/realms/commons
```  

#### **- Custom Pages**

By default the proxy will immediately redirect you for authentication and hand back 403 for access denied. Most users will probably want to present the user with a more friendly
sign-in and access denied page. You can pass the command line options (or via config file) paths to the files i.e. --signin-pag=PATH. The sign-in page will have a 'redirect'
passed into the scope hold the oauth redirection url. If you wish pass additional variables into the templates, perhaps title, sitename etc, you can use the --tag key=pair i.e.
--tag title="This is my site"; the variable would be accessible from {{ .title }}

```HTML
<html>
<body>
<a href="{{ .redirect }}">Sign-in</a>
</body>
</html>
```

#### **- White-listed URL's**

Depending on how the application urls are laid out, you might want protect the root / url but have exceptions on a list of paths, i.e. /health etc. Although you should probably
fix this by fixing up the paths, you can add excepts to the protected resources. (Note: it's an array, so the order is important)

```YAML
  resources:
  - url: /some_white_listed_url
    white-listed: true
  - url: /
    methods:
      - GET
    roles:
      - <CLIENT_APP_NAME>:<ROLE_NAME>
      - <CLIENT_APP_NAME>:<ROLE_NAME>
```

Or on the command line

```shell
  --resource "uri=/some_white_listed_url,white-listed=true"
  --resource "uri=/"  # requires authentication on the rest
  --resource "uri=/admin|roles=admin,superuser|methods=POST,DELETE
```

#### **- Mutual TLS**

The proxy support enforcing mutual TLS for the clients by simply adding the --tls-ca-certificate command line option or config file option. All clients connecting must present a ceritificate
which was signed by the CA being used.

#### **- Refresh Tokens &Stores**

Refresh tokens are either be stored as an encrypted cookie or placed (encrypted) in a shared / local store. At present, redis and boltdb are the only two methods supported. To enable a local boltdb store. --store-url boltdb:///PATH or relative path boltdb://PATH. For redis the option is redis://HOST:PORT. In both cases the refresh token is encrypted before placing into the store

#### **- Refresh Tokens**

Assuming access response responds with a refresh token and the --enable-refresh-token is true, the proxy will automatically refresh the access token for you. The tokens themselves are kept either as an encrypted (--encryption-key=KEY) cookie (cookie name: kc-state). Alternatively you can place the refresh token (still requires encryption key) in a local boltdb file or shared redis. Naturally the encryption key has to be the same on all instances and boltdb is for single instance only developments.

#### **- Logout Endpoint**

A /oauth/logout?redirect=url is provided as a helper to logout the users, aside from dropping a sessions cookies, we also attempt to refrevoke session access via revocation url (config revocation-url or --revocation-url) with the provider. For keycloak the url for this would be https://keycloak.example.com/auth/realms/REALM_NAME/protocol/openid-connect/logout, for google /oauth/revoke

#### **- Cross Origin Resource Sharing (CORS)**

You are permitted to add CORS following headers into the /oauth uri namespace

 * Access-Control-Allow-Origin
 * Access-Control-Allow-Methods
 * Access-Control-Allow-Headers
 * Access-Control-Expose-Headers
 * Access-Control-Allow-Credentials
 * Access-Control-Max-Age

Either from the config file:

```YAML
cors:
  origins:
  - '*'
  methods:
  - GET
  - POST
```

or via the command line arguments

```shell
--cors-origins [--cors-origins option]                  a set of origins to add to the CORS access control (Access-Control-Allow-Origin)
--cors-methods [--cors-methods option]                  the method permitted in the access control (Access-Control-Allow-Methods)
--cors-headers [--cors-headers option]                  a set of headers to add to the CORS access control (Access-Control-Allow-Headers)
--cors-exposes-headers [--cors-exposes-headers option]  set the expose cors headers access control (Access-Control-Expose-Headers)
```

#### **- Upsteam URL**

You can control the upstream endpoint via the --upstream-url or config option. Both http and https is supported and you can control
the TLS verification via the --skip-upstream-tls-verify or config option, along with enabling or disabling keepalives on the upstream via
--upstream-keepalives option. Note, the proxy can also upstream via a unix socket, --upstream-url unix://path/to/the/file.sock

#### **- Endpoints**

* **/oauth/authorize** is authentication endpoint which will generate the openid redirect to the provider
* **/oauth/callback** is provider openid callback endpoint
* **/oauth/expired** is a helper endpoint to check if a access token has expired, 200 for ok and, 401 for no token and 401 for expired
* **/oauth/health** is the health checking endpoint for the proxy
* **/oauth/login** provides a relay endpoint to login via grant_type=password i.e. POST /oauth/login?username=USERNAME&password=PASSWORD
* **/oauth/logout** provides a convenient endpoint to log the user out, it will always attempt to perform a back channel logout of offline tokens
* **/oauth/token** is a helper endpoint which will display the current access token for you
