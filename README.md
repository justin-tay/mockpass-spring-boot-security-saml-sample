Spring Boot Sample SAML 2.0 Service Provider for SingPass/CorpPass
====================

> Forked from spring-boot-security-saml-sample (https://github.com/vdenotaris/spring-boot-security-saml-sample)

---------

<img src="https://i.ibb.co/CKbFBzH/logo-small.png" align="right" />

## Project description

This project represents a sample implementation of a **SAML 2.0 Service Provider**, completely built on **Spring Framework**. In particular, it shows how to develop a web solution devised for Federated Authentication, by integrating **Spring Boot** and **Spring Security SAML**. The configuration has been completely defined using *Java annotations* (no XML).

**MockPass** ([mockpass](https://github.com/opengovsg/mockpass)) is used as public Identity Provider for test purpose.

- **Original Author:** Vincenzo De Notaris ([dev@vdenotaris.com](mailto:dev@vdenotaris.com))
- **Website:** [www.vdenotaris.com](http://www.vdenotaris.com)

---------

## Walkthrough

### Installing and running the sample Service Provider

```
mvn install

java -jar target/mockpass-spring-boot-security-saml-sample-1.0.0.RELEASE.jar
```

### Configuring MockPass as the Identity Provider

Use the following environment variables when configuring MockPass

```
SINGPASS_ASSERT_ENDPOINT=http://localhost:8080/saml/SSO
CORPPASS_ASSERT_ENDPOINT=http://localhost:8080/saml/SSO
SHOW_LOGIN_PAGE=true
```

### Testing the sample Service Provider

Access the application at http://localhost:8080/landing

View the SP metadata at http://localhost:8080/saml/metadata 

---------

### Run as Docker container

#### Running Docker Natively

```
docker run -it --rm -p 8080:8080 -t justintay/mockpass-spring-saml-sp:latest
```

Access the application at http://localhost:8080/landing

#### Running Docker Machine

Use 'docker-machine ip default' to get the IP address of the Docker host. You will then need to configure the SINGPASS_IDP_ID and CORPPASS_IDP_IP environment variables so that the Service Provider knows how to talk to MockPass.

```
docker run -it --rm -p 8080:8080 -e SINGPASS_IDP_ID=http://mockpass-host:5156/singpass/saml20 -e CORPPASS_IDP_ID=http://mockpass-host:5156/corppass/saml20 -t justintay/mockpass-spring-saml-sp:latest
```

Access the application at http://DOCKER-MACHINE-HOST:8080/landing

*Note: the related Docker image is publicly available on [Docker Hub](https://hub.docker.com/r/justintay/mockpass-spring-saml-sp).*

### Run using Docker Compose

Edit the .env file to indicate the ip address of the docker host.

Note that this will run both the sample Service Provider as well as MockPass.

```
docker-compose up
```

---------

### References

#### Spring Boot Sample SAML 2.0 Service Provider

> The original sample that the code is based on.
> - **Ref.:** [https://vdenotaris.github.io/spring-boot-security-saml-sample/](https://vdenotaris.github.io/spring-boot-security-saml-sample/)

#### Spring Boot

> Spring Boot makes it easy to create Spring-powered, production-grade applications and services with absolute minimum fuss.  It takes an opinionated view of the Spring platform so that new and existing users can quickly get to the bits they need.
> - **Ref.:** [http://projects.spring.io/spring-boot/](http://projects.spring.io/spring-boot/)

#### Spring Security SAML Extension

> Spring SAML Extension allows seamless inclusion of SAML 2.0 Service Provider capabilities in Spring applications. All products supporting SAML 2.0 in Identity Provider mode (e.g. ADFS 2.0, Shibboleth, OpenAM/OpenSSO, Ping Federate, Okta) can be used to connect with Spring SAML Extension.
> - **Ref.:** [http://projects.spring.io/spring-security-saml/](http://projects.spring.io/spring-security-saml/)

------

### License

    Copyright 2019 Vincenzo De Notaris
    Copyright 2019 Justin Tay

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	    http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

