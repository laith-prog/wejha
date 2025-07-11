# JWT Authentication

This module provides JWT authentication for the application. It includes:

- Access tokens with a short TTL (15 minutes by default)
- Refresh tokens with a long TTL (30 days by default)
- Token refresh endpoint
- Google OAuth integration
- Password reset via email verification

## Authentication Flow

1. **Login**: Use `/api/v1/login` to authenticate with email and password
2. **Google Auth**: Use `/api/v1/auth/google` for Google OAuth authentication
3. **Token Refresh**: Use `/api/v1/auth/refresh` to get new tokens using your refresh token
4. **Protected Routes**: Access protected routes by including the access token in the Authorization header
5. **Password Reset**: Use the forgot password flow to reset your password via email verification

## API Endpoints

### Public Endpoints

- `POST /api/v1/login` - Login with email and password
- `POST /api/v1/register/complete` - Complete registration after email verification
- `POST /api/v1/auth/set-password` - Set or reset password
- `GET /api/v1/auth/google` - Google OAuth authentication
- `POST /api/v1/auth/refresh` - Refresh access token using refresh token
- `POST /api/v1/auth/forgot-password` - Request password reset code
- `POST /api/v1/auth/verify-reset-code` - Verify password reset code
- `POST /api/v1/auth/reset-password` - Reset password after verification

### Protected Endpoints

- `POST /api/v1/logout` - Logout (invalidate token)
- `GET /api/v1/user` - Get authenticated user information
- `GET /api/v1/auth/test` - Test JWT authentication

## Usage Examples

### Login

```http
POST /api/v1/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "YourPassword123!"
}
```

Response:

```json
{
  "message": "Login successful",
  "status": "success",
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      ...
    },
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "access",
    "expires_in": 900
  }
}
```

### Refresh Token

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

Response:

```json
{
  "message": "Token refreshed successfully",
  "status": "success",
  "data": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "access",
    "expires_in": 900
  }
}
```

### Accessing Protected Routes

Include the access token in the Authorization header:

```http
GET /api/v1/user
Authorization: Access eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### Password Reset Flow

1. Request a password reset code:

```http
POST /api/v1/auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

2. Verify the code sent to the email:

```http
POST /api/v1/auth/verify-reset-code
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "123456"
}
```

3. Reset the password with a new one:

```http
POST /api/v1/auth/reset-password
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "NewPassword123!",
  "password_confirmation": "NewPassword123!"
}
```

## Configuration

JWT configuration can be modified in `config/jwt.php`:

- `ttl`: Access token lifetime in minutes (default: 15)
- `refresh_ttl`: Refresh token lifetime in minutes (default: 43200 - 30 days) 