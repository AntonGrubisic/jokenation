This project implements a secure microservices architecture using Spring Boot, Spring Security, and Spring Authorization Server. It includes an Authorization Server, an API Gateway, and two protected microservices: Joke Service and Quote Service. JWT tokens are used to secure communication, and the system can be deployed using Docker Compose or on Kubernetes with Ingress as the entry point.

The project demonstrates:

Issuing JWT tokens using the OAuth2 Client Credentials flow

Routing and securing API requests via the API Gateway

Access control based on token scopes (jokes.read, quotes.read)

Full deployment in Kubernetes, including Ingress routing



➤ 1. Build the Services
You can use the provided rebuild.ps1 (or rebuild.sh on Unix-based systems) to build Docker images for all services:

bash
./rebuild.ps1

bash
docker-compose build

➤ 2. Start All Services
Run the system locally with:

docker-compose up
All services will run in a shared Docker network (microservices-net) and expose their respective ports:

Auth Service: localhost:9000

API Gateway: localhost:8081

Joke Service: internal only (port 8083 inside container)

Quote Service: internal only (port 8082 inside container)
