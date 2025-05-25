🌍 Django Microservices System with JWT Authentication
A scalable, modular microservices architecture built using Django REST Framework, supporting secure Authentication, Banking, and Payment operations. It features JWT authentication with RSA asymmetric encryption, seamless container orchestration using Docker Compose, and production-grade deployment with Gunicorn, Uvicorn, and Nginx.

🧩 Overview of Services
Service	Description
🔐 Auth	Issues & validates JWTs for secure access across services
🏦 Bank	Manages user banking operations (accounts, balances)
💳 Payment	Processes transactions and payment requests
🌐 Gateway	Nginx reverse proxy + static/media file handler

All services are containerized, isolated via Docker private networks, and securely interconnected.

🧱 System Architecture
markdown
Copy
Edit
                      ┌─────────────────────────────┐
                      │        NGINX Gateway        │
                      └────────────┬────────────────┘
                                   │
 ┌─────────────────────────────────┼──────────────────────────────────┐
 │                                 │                                  │
 │                            ┌────▼────┐                        ┌────▼─────┐
 │                            │  Auth   │                        │  Bank     │
 │                            └────┬────┘                        └────┬─────┘
 │                                 │                                  │
 │                            ┌────▼─────┐                       ┌────▼──────┐
 │                            │ Payment  │                       │ PostgreSQL │
 │                            └──────────┘                       └────────────┘
 │
 └──────────────────────────── Docker Private Network ───────────────────────────
⚙️ Technology Stack
🐍 Python 3.11+

⚙️ Django 4+

🔐 Django REST Framework + SimpleJWT (RSA keys)

🐳 Docker & Docker Compose

🌐 Nginx – Reverse proxy & static/media handler

🐘 PostgreSQL – Shared database engine

🚀 Gunicorn + Uvicorn workers – ASGI-compatible application server

🔐 Authentication Flow (JWT with RSA)
The Auth Service manages user login and token issuance using asymmetric encryption.

🔄 Endpoints
POST /api/token/ — Get access & refresh tokens

POST /api/token/refresh/ — Refresh the access token

Headers:

http
Copy
Edit
Authorization: Bearer <your_token>
✅ RSA encryption ensures the access token is signed using the private key and verified using the public key.

🚀 Getting Started
📦 Prerequisites
Docker

Docker Compose

🛠️ Setup
bash
Copy
Edit
git clone https://github.com/Iradukunda-Fils/Simple-Micro-Service.git
cd Simple-Micro-Service
docker-compose up --build
🌐 Service Endpoints
Service	URL
Auth	http://localhost/auth/
Bank	http://localhost/bank/
Payment	http://localhost/payment/
Admin	http://localhost/admin/

📁 Static & Media Files
Managed via Django's collectstatic

Served through Nginx from Docker-mounted volumes

📂 Project Structure
bash
Copy
Edit
Simple-Micro-Service/
├── auth_service/         # Authentication microservice
├── bank_service/         # Banking microservice
├── payment_service/      # Payment microservice
├── nginx/                # Reverse proxy configuration
├── shared_db/            # PostgreSQL container
├── docker-compose.yml    # Multi-service orchestration
└── .env                  # Environment variables
✅ Key Features
🔐 JWT Auth with RSA Encryption

🔄 Refresh Token Support

🧱 Service-Based Separation of Concerns

🐳 Isolated Dockerized Microservices

🔧 Production-Ready: Gunicorn + Uvicorn

🌐 Centralized Static & Media Handling via Nginx

🔒 Secure Internal Networking

🛠️ Future Enhancements
📊 Prometheus & Grafana for monitoring

⚙️ GitHub Actions CI/CD

🧠 Service Discovery (e.g., using Consul)

📘 Swagger/OpenAPI for per-service docs

📦 Centralized Logging (e.g., ELK Stack)


👤 Author
**Iradukunda Fils**
🔗 [GitHub Profile](https://github.com/Iradukunda-Fils)

📄 License
Licensed under the MIT License — feel free to use, modify, and contribute.