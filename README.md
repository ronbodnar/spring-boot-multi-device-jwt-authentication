# Spring Boot Multi-Device JWT Authentication

A Java 21 authentication service built with Spring Boot 4.1 and Spring Security 7.1. It demonstrates multi-device JWT authentication with cookie-based access and refresh tokens, keeping refresh-token sessions separate across client installations.

## Features

- Short-lived access JWTs and longer-lived refresh JWTs in `HttpOnly` cookies.
- A client-provided `sessionId` associates tokens with one client installation. Refreshing rotates that session's refresh token without invalidating other sessions.
- BCrypt password hashing and Spring Security authorization.
- Registration, account update, password-reset request, and reset endpoints.
- H2 in-memory database for local development; Redis stores password-reset tokens.

## Requirements

- Java 21
- OpenSSL (to generate a local JWT signing key)
- Docker with the Compose plugin, or a locally running Redis server

## Quickstart

Clone the repository and create local configuration:

```bash
git clone https://github.com/ronbodnar/spring-boot-multi-device-jwt-authentication.git
cd spring-boot-multi-device-jwt-authentication
cp env.properties.example env.properties
```

Replace the sample `JWT_SECRET` in `env.properties` with a fresh Base64-encoded random key. For example:

```bash
openssl rand -base64 32
```

Start Redis and the application:

```bash
docker compose up -d redis
./mvnw spring-boot:run
```

The service listens on `http://localhost:8080`. `env.properties` is ignored by Git; do not commit real secrets.

Run tests with:

```bash
./mvnw test
```

## API usage

The service sets the `app_access` and `app_refresh` cookies after registration or login. Keep cookies enabled in your HTTP client and include them in subsequent requests. Both cookies are `HttpOnly` and use `SameSite=Strict`; the `Secure` attribute is enabled when the active Spring profile starts with `prod`.

Generate and persist a distinct UUID `sessionId` for each client installation. Reuse that ID when that installation logs in again; use another ID for another device or browser profile.

### Register

```bash
SESSION_ID="$(cat /proc/sys/kernel/random/uuid)"

curl -i -c cookies.txt \
  -H 'Content-Type: application/json' \
  -d "{
    \"username\":\"alice\",
    \"password\":\"correct-horse-battery\",
    \"confirmPassword\":\"correct-horse-battery\",
    \"email\":\"alice@example.com\",
    \"givenName\":\"Alice\",
    \"familyName\":\"Example\",
    \"sessionId\":\"${SESSION_ID}\"
  }" \
  http://localhost:8080/api/v1/auth/register
```

Registration returns the created user and sets both auth cookies.

### Login and get the current user

```bash
SESSION_ID="$(cat /proc/sys/kernel/random/uuid)"

curl -i -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice\",\"password\":\"correct-horse-battery\",\"sessionId\":\"${SESSION_ID}\"}" \
  http://localhost:8080/api/v1/auth/login

curl -i -b cookies.txt http://localhost:8080/api/v1/auth/me
```

Persist the session ID for the lifetime of that client installation. The cookie jar in this example is for illustration; browsers manage cookies automatically.
For the same installation, reuse its previously stored session ID when logging in; generate a new ID only for a separate client session. The snippets generate IDs independently so each can be copied on its own.

### Refresh and logout

```bash
curl -i -b cookies.txt -c cookies.txt \
  http://localhost:8080/api/v1/auth/refresh

curl -i -b cookies.txt -c cookies.txt \
  -X POST http://localhost:8080/api/v1/auth/logout
```

Refresh replaces the cookies for that session. Logout clears the cookies and revokes that refresh token on the server. Access tokens remain usable until they expire.

### Endpoint reference

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/auth/register` | Create an account and sign in |
| `POST` | `/api/v1/auth/login` | Sign in to a client session |
| `GET` | `/api/v1/auth/refresh` | Rotate tokens using the refresh cookie |
| `POST` | `/api/v1/auth/logout` | Revoke the current refresh token and clear auth cookies |
| `GET` | `/api/v1/auth/me` | Get the authenticated user |
| `PUT` | `/api/v1/auth/me` | Update the authenticated user's profile |
| `POST` | `/api/v1/auth/request-password-reset` | Request a password-reset token |
| `POST` | `/api/v1/auth/reset-password` | Reset a password using a token |
| `GET` | `/api/v1/identity/users/{id}/summary` | Get a user summary |
| `GET` | `/api/v1/identity/users/{id}` | Get the authenticated user's account |

## Events

The service publishes events for user registration, password-reset requests, and password changes. The included listeners currently log these events rather than performing external actions. Use them as extension points to send email or trigger other application-specific workflows.

## Configuration

The local configuration file (`env.properties`) is imported when present. `JWT_SECRET` must be a Base64-encoded key with at least 256 bits of key material. Other settings, including token lifetimes, cookie names, and server port, are in [`application.yml`](src/main/resources/application.yml).

Redis uses Spring Boot's default local connection (`localhost:6379`). The included Compose file starts an unauthenticated Redis instance for local development only.

## Project layout

Java sources under `src/main/java/com/ronbodnar/auth` are organized by feature: `auth`, `identity`, `security`, `config`, and `exception`.

## Contributing

Issues and pull requests are welcome. Please include tests for behavior changes and avoid committing `env.properties` or other secrets.

## License

MIT. See [LICENSE](LICENSE).
