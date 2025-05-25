# 🌍 Simple Microservices System with Django & JWT

A scalable microservices-based system developed in **Django REST Framework**, designed to support **Authentication**, **Banking**, and **Payment Services** — secured using **JWT authentication** with **asymmetric encryption** (RSA). It uses **Docker Compose** for orchestration, **Nginx** for reverse proxying, and **Gunicorn** for production-grade deployment.

---

## 🔧 Services Overview

| Service          | Description                                   |
|------------------|-----------------------------------------------|
| 🔐 **Auth**       | Centralized user authentication using JWT     |
| 🏦 **Bank**       | Manages banking operations                    |
| 💳 **Payment**    | Handles payment processing                    |
| 🌐 **Gateway**    | Nginx-based reverse proxy and static file handler |

Each service is **Dockerized**, network-isolated, and communicates securely using internal Docker networking.

---

## 🧱 Architecture Diagram

            ┌─────────────────────────────┐
            │        NGINX Gateway        │
            └────────────┬────────────────┘
                         │
 ┌──────────────────────┼─────────────────────────────┐
 │                      │                             │
┌───▼────┐ ┌─────▼─────┐ ┌──────▼─────┐
│ Auth │ │ Bank │ │ Payment │
└───▲────┘ └─────▲─────┘ └──────▲─────┘
│ │ │
│ Central PostgreSQL Database │
└────────────────────────┬─────────────────────────────┘
│


---

Docker Private Network

## ⚙️ Tech Stack

- 🐍 **Python 3.11+**
- 🧰 **Django 4+**
- 🛡 **Django REST Framework**
- 🔐 **SimpleJWT with RSA keys**
- 🐳 **Docker & Docker Compose**
- 🌐 **Nginx** as reverse proxy/static handler
- 🐘 **PostgreSQL** for all services
- 🚀 **Gunicorn** with **Uvicorn workers** for performance

---

## 🔐 Authentication Flow

The **Auth service** issues and verifies JWT tokens using **asymmetric RSA encryption**.

- `/api/token/` → Get Access and Refresh tokens  
- `/api/token/refresh/` → Refresh the Access token

Add the JWT token in your headers:

```http
Authorization: Bearer <your_token>

Thank you for the clarification — since your **microservices architecture is built using Django (not FastAPI)**, let's rewrite your `README.md` accordingly.

Here's an **updated, clean, attractive, and Django-specific README** for your microservice system using **JWT with asymmetric encryption**, **Docker Compose**, **Gunicorn + Uvicorn**, and **Nginx reverse proxy**:

---

```markdown
# 🌍 Simple Microservices System with Django & JWT

A scalable microservices-based system developed in **Django REST Framework**, designed to support **Authentication**, **Banking**, and **Payment Services** — secured using **JWT authentication** with **asymmetric encryption** (RSA). It uses **Docker Compose** for orchestration, **Nginx** for reverse proxying, and **Gunicorn** for production-grade deployment.

---

## 🔧 Services Overview

| Service          | Description                                   |
|------------------|-----------------------------------------------|
| 🔐 **Auth**       | Centralized user authentication using JWT     |
| 🏦 **Bank**       | Manages banking operations                    |
| 💳 **Payment**    | Handles payment processing                    |
| 🌐 **Gateway**    | Nginx-based reverse proxy and static file handler |

Each service is **Dockerized**, network-isolated, and communicates securely using internal Docker networking.

---

## 🧱 Architecture Diagram

```

```
            ┌─────────────────────────────┐
            │        NGINX Gateway        │
            └────────────┬────────────────┘
                         │
 ┌──────────────────────┼─────────────────────────────┐
 │                      │                             │
```

┌───▼────┐           ┌─────▼─────┐                ┌──────▼─────┐
│  Auth  │           │  Bank     │                │  Payment   │
└───▲────┘           └─────▲─────┘                └──────▲─────┘
│                        │                              │
│           Central PostgreSQL Database                │
└────────────────────────┬─────────────────────────────┘
│
Docker Private Network

````

---

## ⚙️ Tech Stack

- 🐍 **Python 3.11+**
- 🧰 **Django 4+**
- 🛡 **Django REST Framework**
- 🔐 **SimpleJWT with RSA keys**
- 🐳 **Docker & Docker Compose**
- 🌐 **Nginx** as reverse proxy/static handler
- 🐘 **PostgreSQL** for all services
- 🚀 **Gunicorn** with **Uvicorn workers** for performance

---

## 🔐 Authentication Flow

The **Auth service** issues and verifies JWT tokens using **asymmetric RSA encryption**.

- `/api/token/` → Get Access and Refresh tokens  
- `/api/token/refresh/` → Refresh the Access token

Add the JWT token in your headers:

```http
Authorization: Bearer <your_token>
````

---

## 🚀 Running the Project

### 📦 Prerequisites

* Docker
* Docker Compose

### 🛠️ Setup & Run

```bash
git clone https://github.com/Iradukunda-Fils/Simple-Micro-Service.git
cd Simple-Micro-Service
docker-compose up --build
```

Once running:

| Service            | URL                         |
| ------------------ | --------------------------- |
| Auth               | `http://localhost/auth/`    |
| Bank               | `http://localhost/bank/`    |
| Payment            | `http://localhost/payment/` |
| Admin (if exposed) | `http://localhost/admin/`   |

---

## 📁 Static & Media Files

* Handled by **Nginx**
* Collected via Django’s `collectstatic`
* Served from mounted Docker volume paths

---

## 🔐 JWT with RSA

* Secure authentication with **private/public key pair**
* Keys should be stored securely in `.env` or mounted volumes

> ✅ Token decoding uses the **public key**, encoding uses the **private key**

---

## 📂 Project Structure

```
Simple-Micro-Service/
├── auth_service/
├── bank_service/
├── payment_service/
├── nginx/
├── shared_db/ (PostgreSQL)
├── docker-compose.yml
└── .env
```

---

## ✅ Features

* 🔐 **Centralized Auth with JWT**
* 🔄 **Refresh tokens**
* 🧱 **Service-to-service separation**
* 🐳 **Isolated services with Docker**
* 🔧 **Gunicorn for production WSGI**
* 🌐 **Nginx for static/media + gateway**
* 🔒 **Private Docker networks**
* 🧪 Easily testable & extendable structure

---

## 🛠️ Future Improvements

* 📊 Monitoring with Prometheus & Grafana
* 📦 CI/CD with GitHub Actions
* 🔎 Centralized Logging (ELK Stack)
* 📘 Swagger/OpenAPI docs per service
* 🧩 Service discovery (e.g., with Consul)

---

## 👤 Author

**Iradukunda Fils**
🔗 [GitHub Profile](https://github.com/Iradukunda-Fils)

---

## 📄 License

This project is licensed under the MIT License.

---

```

---


```

