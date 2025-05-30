This project implements a secure microservices architecture using Spring Boot, Spring Security, and Spring Authorization Server. It includes an Authorization Server, an API Gateway, and two protected microservices: Joke Service and Quote Service. JWT tokens are used to secure communication, and the system can be deployed using Docker Compose or on Kubernetes with Ingress as the entry point.

The project demonstrates:

Issuing JWT tokens using the OAuth2 Client Credentials flow

Routing and securing API requests via the API Gateway

Access control based on token scopes (jokes.read, quotes.read)

Full deployment in Kubernetes, including Ingress routing



# Jokenation – Microservices with Kubernetes and JWT Security

This project consists of several microservices running in Kubernetes, secured using an Authorization Server that issues JWT tokens. A Gateway service acts as the single entry point, exposed through an Ingress.

## 🚀 Overview

- 🧩 Microservices: `authservice`, `jokeservice`, `quoteservice`, `gateway`
- 🔐 Security: OAuth2 (Client Credentials Grant) with JWT
- 🌐 Ingress: Entry via `http://jokenation.local`

---

## 📦 Build & Deploy

### 1. Build services locally (Maven)

```bash
./mvnw clean package -DskipTests



All services will run in a shared Docker network (microservices-net) and expose their respective ports:

Auth Service: localhost:9000

API Gateway: localhost:8081

Joke Service: internal only (port 8083 inside container)

Quote Service: internal only (port 8082 inside container)

docker build -t authservice:0.0.1-SNAPSHOT ./authservice
docker build -t jokeservice:0.0.1-SNAPSHOT ./jokeservice
docker build -t quoteservice:0.0.1-SNAPSHOT ./quoteservice
docker build -t gateway:0.0.1-SNAPSHOT ./gateway

Deploy to kubernetes:
kubectl apply -f k8s/ -n jokenation

Create a curlpod for internal cluster testing:
kubectl run curlpod --image=curlimages/curl:latest -n jokenation --restart=Never --command -- sleep 3600
kubectl exec -it curlpod -n jokenation -- sh

Get access token:
curl -X POST http://authservice:9000/oauth2/token \
  -u client-id:secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=jokes.read quotes.read"
