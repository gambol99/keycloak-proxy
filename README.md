# Signal Louketo Fork

Signal AI specific additions to Louketo Proxy

## Releasing

To release changes follow the instructions in [the releasing documentation](docs/release.md). This uses GitHub Actions.

# EOL notice

Louketo Proxy reached end of line in November 21, 2020. This means that we no longer support, or update it. The details are available [here](https://www.keycloak.org/2020/08/sunsetting-louketo-project.adoc).

## Louketo Proxy

This repository is a work in progress and contains the source code for the Louketo Proxy. You should be able to see what's being planned at our [milestones page](https://github.com/louketo/louketo-proxy/milestones).

## Help and Documentation

* [Louketo Proxy documentation](docs/user-guide.md)
* [Mailing List](https://groups.google.com/forum/#!forum/louketo) - Mailing list for help and general questions about Keycloak
* [Issue Tracker](https://github.com/louketo/louketo-proxy/issues) - Issue tracker for bugs and feature requests


## Reporting Security Vulnerabilities

If you've found a security vulnerability, please report send an e-mail to <louketo-security@googlegroups.com>


## Reporting an issue

If you believe you have discovered a defect in Louketo Proxy please open an issue in our [Issue Tracker](https://github.com/louketo/louketo-proxy/issues).
Please remember to provide a good summary, description as well as steps to reproduce the issue.


## Getting started

To run Louketo Proxy, please refer to our [building and working with the code base](docs/building.md) guide. Alternatively, you can use the Docker image by running:

    docker run -it --rm quay.io/louketo/louketo-proxy \
      --listen 127.0.0.1:8080 \
      --upstream-url http://127.0.0.1:80 \
      --discovery-url https://keycloak.example.com/auth/realms/<REALM_NAME> \
      --client-id <CLIENT_ID>
    
For more details refer to the [Documentation](docs/user-guide.md).

### Writing Tests

To write tests refer to the [writing tests](docs/tests-development.md) guide.

## Contributing

Before contributing to Louketo Proxy please read our [contributing guidelines](CONTRIBUTING.md).

## Other Keycloak Projects

* [Keycloak](https://github.com/keycloak/keycloak) - Keycloak Server and Java adapters
* [Keycloak Documentation](https://github.com/keycloak/keycloak-documentation) - Documentation for Keycloak
* [Keycloak QuickStarts](https://github.com/keycloak/keycloak-quickstarts) - QuickStarts for getting started with Keycloak

## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
