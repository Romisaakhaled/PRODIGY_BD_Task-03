# Task 3 - JWT Authentication API

This project is a simple demonstration of **JWT Authentication and Authorization** using `.NET 8 Web API`.

## 🔐 Features
- User Registration
- User Login with JWT token generation
- Protected endpoints with roles (`admin`, `user`, `owner`)
- Role-based access using `[Authorize]` attributes

## 🚀 Technologies Used
- .NET 8
- JWT (Json Web Tokens)
- BCrypt for password hashing
- In-memory user storage
- Swagger for API testing


## 📷 Sample Endpoints
- `POST /register` – Register new user
- `POST /login` – Get JWT token
- `GET /admin` – Admin-only route
- `GET /user` – User-only route
- `GET /owner` – Owner-only route
- `GET /profile` – Any logged-in user
