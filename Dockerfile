FROM alpine:3.2
MAINTAINER Rohith <gambol99@gmail.com>

ADD bin/keycloak-proxy /opt/bin/keycloak-proxy
RUN chmod +x /opt/bin/keycloak-proxy

WORKDIR "/opt/bin"

ENTRYPOINT [ "/opt/bin/keycloak-proxy" ]
