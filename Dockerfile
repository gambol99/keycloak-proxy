FROM alpine:3.2
MAINTAINER Rohith <gambol99@gmail.com>

RUN apk update && \
    apk add ca-certificates

ADD bin/keycloak-proxy /opt/bin/oidc-proxy
RUN chmod +x /opt/bin/keycloak-proxy

WORKDIR "/opt/bin"

ENTRYPOINT [ "/opt/bin/keycloak-proxy" ]
