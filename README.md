# Spring Boot JWT Authentication (Access + Refresh Token)

A lightweight and secure authentication system built with Spring Boot, implementing JWT-based access and refresh tokens, refresh token rotation, and concurrency-safe token handling using pessimistic locking. The project emphasizes clean architecture, secure cookie-based token storage, and standardized API responses.

---

## 🚀 Features

- **JWT-based authentication** with Access and Refresh tokens  
- **Refresh token rotation** (old refresh token is invalidated after use)  
- **Concurrency-safe token handling** using pessimistic locking  
- **HTTP-only cookies** for secure token storage  
- **Spring Security** integration  
- Clean and consistent API responses with standardized error handling  
- Modular architecture with Controller → Service → Facade layers  
- Secure password hashing using **Argon2**  
- Global exception handling for consistent error responses  

---

## 🧱 Architecture


---

## 🧾 API Endpoints

| Method | Endpoint              | Description                     |
|--------|-----------------------|---------------------------------|
| POST   | `/auth/register`      | User registration               |
| POST   | `/auth/login`         | User login                      |
| GET    | `/auth/user`          | Fetch authenticated user info   |
| POST   | `/auth/refresh_token` | Rotate tokens and refresh cookies |

---

## 🔐 Security

### Token Handling
- Access token expires in **15 minutes**
- Refresh token expires in **7 days**
- Refresh token is stored in the database (by JTI) and deleted after rotation

### Cookie Security
Tokens are stored in **HTTP-only cookies** with the following settings:
- `Secure`
- `SameSite=None`
- `HttpOnly`
- `Max-Age=24 hours`

---

## 📌 Key Components

### `SecurityConfig`
Configures Spring Security, disables sessions, and sets up JWT filters.

### `JwtFilter`
Validates access token from cookie, sets authentication in SecurityContext.

### `JwtErrorFilter`
Handles JWT errors and returns consistent JSON error responses.

### `JwtTokenProvider`
Generates and validates access & refresh tokens using a secret key.

### `RefreshTokenService`
Manages refresh token storage and rotation.

### `AuthFacade`
Creates tokens, saves refresh token, and sets cookies in response.

---

## 📦 Tech Stack

- Java 17
- Spring Boot
- Spring Security
- JWT (jjwt)
- PostgreSQL
- Argon2 password hashing
- Maven

---
