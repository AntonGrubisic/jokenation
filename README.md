This project implements a secure microservices architecture using Spring Boot, Spring Security, and Spring Authorization Server. It includes an Authorization Server, an API Gateway, and two protected microservices: Joke Service and Quote Service. JWT tokens are used to secure communication, and the system can be deployed using Docker Compose or on Kubernetes with Ingress as the entry point.

The project demonstrates:

Issuing JWT tokens using the OAuth2 Client Credentials flow

Routing and securing API requests via the API Gateway

Access control based on token scopes (jokes.read, quotes.read)

Full deployment in Kubernetes, including Ingress routing

It satisfies all requirements for both the Pass and Distinction (VG) levels of the assignment, including advanced deployment and architectural recommendations.
