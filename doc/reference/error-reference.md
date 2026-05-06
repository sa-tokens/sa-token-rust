# SaToken Error Reference

## English

### Error Categories

sa-token-rust provides 32 error types organized into 10 categories:

#### 1. Basic Token Errors

##### TokenNotFound
- **Message**: "Token not found or expired"
- **Description**: The requested token does not exist in storage or has expired
- **Common Causes**: Token was never created, expired naturally, or manually deleted
- **Solution**: User needs to log in again to obtain a new token

##### InvalidToken
- **Message**: "Token is invalid: {reason}"
- **Description**: The token format or content is invalid
- **Common Causes**: Corrupted token, tampered token, or wrong token format
- **Solution**: Verify token integrity and ensure correct token format

##### TokenExpired
- **Message**: "Token has expired"
- **Description**: The token has passed its expiration time
- **Common Causes**: Token timeout exceeded configured duration
- **Solution**: Use refresh token to get a new access token or re-authenticate

#### 2. Authentication Errors

##### NotLogin
- **Message**: "User not logged in"
- **Description**: User is attempting to access a protected resource without authentication
- **Common Causes**: No token provided, token not found in request
- **Solution**: User must log in first to obtain a valid token

#### 3. Authorization Errors

##### PermissionDenied
- **Message**: "Permission denied: missing permission '{permission}'"
- **Description**: User lacks the required permission to perform the action
- **Common Causes**: Insufficient permissions assigned to the user
- **Solution**: Grant the required permission to the user or role

##### RoleDenied
- **Message**: "Role denied: missing role '{role}'"
- **Description**: User does not have the required role
- **Common Causes**: User not assigned to the necessary role
- **Solution**: Assign the required role to the user

#### 4. Account Status Errors

##### AccountBanned
- **Message**: "Account is banned until {time}"
- **Description**: The account has been temporarily or permanently banned
- **Common Causes**: Violation of terms, security issues, or administrative action
- **Solution**: Wait until ban expires or contact administrator

##### AccountKickedOut
- **Message**: "Account is kicked out"
- **Description**: User session has been forcefully terminated
- **Common Causes**: Administrator kicked the user, concurrent login on another device
- **Solution**: User needs to log in again

#### 5. Session Errors

##### SessionNotFound
- **Message**: "Session not found"
- **Description**: The session does not exist or has been deleted
- **Common Causes**: Session expired, manually deleted, or never created
- **Solution**: Establish a new session by logging in

#### 6. Nonce Errors

##### NonceAlreadyUsed
- **Message**: "Nonce has been used, possible replay attack detected"
- **Description**: The nonce has already been consumed, indicating a potential replay attack
- **Common Causes**: Duplicate request submission, replay attack attempt
- **Solution**: Generate a new nonce for each request

##### InvalidNonceFormat
- **Message**: "Invalid nonce format"
- **Description**: The nonce does not follow the expected format
- **Common Causes**: Corrupted nonce, manually crafted invalid nonce
- **Solution**: Use the standard nonce generation method

##### InvalidNonceTimestamp
- **Message**: "Nonce timestamp is invalid or expired"
- **Description**: The timestamp embedded in the nonce is invalid or outside the valid time window
- **Common Causes**: System time drift, expired nonce, or tampered timestamp
- **Solution**: Synchronize system time and generate a fresh nonce

#### 7. Refresh Token Errors

##### RefreshTokenNotFound
- **Message**: "Refresh token not found or expired"
- **Description**: The refresh token does not exist or has expired
- **Common Causes**: Never issued, expired, or revoked
- **Solution**: User must re-authenticate to get a new refresh token

##### RefreshTokenInvalidData
- **Message**: "Invalid refresh token data"
- **Description**: The stored refresh token data is corrupted or malformed
- **Common Causes**: Storage corruption, tampering, or serialization error
- **Solution**: User must re-authenticate

##### RefreshTokenMissingLoginId
- **Message**: "Missing login_id in refresh token"
- **Description**: The refresh token is missing the required login_id field
- **Common Causes**: Data corruption or incomplete token generation
- **Solution**: Generate a new refresh token

##### RefreshTokenInvalidExpireTime
- **Message**: "Invalid expire time format in refresh token"
- **Description**: The expiration time in refresh token cannot be parsed
- **Common Causes**: Incorrect date format or corrupted data
- **Solution**: Generate a new refresh token with correct format

#### 8. Token Validation Errors

##### TokenEmpty
- **Message**: "Token is empty"
- **Description**: No token value provided
- **Common Causes**: Empty string passed as token
- **Solution**: Provide a valid token value

##### TokenTooShort
- **Message**: "Token is too short"
- **Description**: Token length is below minimum required (8 characters)
- **Common Causes**: Truncated or invalid token
- **Solution**: Provide a complete valid token

##### LoginIdNotNumber
- **Message**: "Login ID is not a valid number"
- **Description**: Failed to parse login ID as a numeric value
- **Common Causes**: Non-numeric login ID when numeric is expected
- **Solution**: Ensure login ID format matches expected type

#### 9. OAuth2 Errors

##### OAuth2ClientNotFound
- **Message**: "OAuth2 client not found"
- **Description**: The OAuth2 client ID does not exist
- **Common Causes**: Unregistered client or incorrect client ID
- **Solution**: Register the client or verify client ID

##### OAuth2InvalidCredentials
- **Message**: "Invalid client credentials"
- **Description**: Client ID and secret combination is invalid
- **Common Causes**: Wrong secret, mistyped credentials
- **Solution**: Verify client credentials are correct

##### OAuth2ClientIdMismatch
- **Message**: "Client ID mismatch"
- **Description**: Client ID doesn't match the expected value
- **Common Causes**: Using wrong client ID for authorization code or refresh token
- **Solution**: Use the correct client ID that initiated the flow

##### OAuth2RedirectUriMismatch
- **Message**: "Redirect URI mismatch"
- **Description**: Redirect URI doesn't match registered URIs
- **Common Causes**: URI not in whitelist, typo in URI
- **Solution**: Use a registered redirect URI

##### OAuth2CodeNotFound
- **Message**: "Authorization code not found or expired"
- **Description**: Authorization code doesn't exist or has expired
- **Common Causes**: Code already used, expired (typically 10 minutes)
- **Solution**: Request a new authorization code

##### OAuth2AccessTokenNotFound
- **Message**: "Access token not found or expired"
- **Description**: OAuth2 access token not found or expired
- **Common Causes**: Token expired (typically 1 hour), revoked, or never issued
- **Solution**: Refresh token or re-authorize

##### OAuth2RefreshTokenNotFound
- **Message**: "Refresh token not found or expired"
- **Description**: OAuth2 refresh token not found or expired
- **Common Causes**: Token expired (typically 30 days), revoked, or never issued
- **Solution**: User must re-authorize

##### OAuth2InvalidRefreshToken
- **Message**: "Invalid refresh token data"
- **Description**: Refresh token data is corrupted or invalid
- **Common Causes**: Data corruption, tampering
- **Solution**: Re-authorize to get new tokens

##### OAuth2InvalidScope
- **Message**: "Invalid scope data"
- **Description**: Scope data is invalid or corrupted
- **Common Causes**: Invalid scope format, unauthorized scope request
- **Solution**: Request valid scopes only

#### 10. System Errors

##### StorageError
- **Message**: "Storage error: {details}"
- **Description**: Error occurred while accessing storage backend
- **Common Causes**: Database connection failure, Redis unavailable, network issues
- **Solution**: Check storage backend status and connectivity

##### ConfigError
- **Message**: "Configuration error: {details}"
- **Description**: Configuration is invalid or missing
- **Common Causes**: Missing required config, invalid config values
- **Solution**: Review and fix configuration

##### SerializationError
- **Message**: "Serialization error: {details}"
- **Description**: Failed to serialize or deserialize data
- **Common Causes**: Data structure mismatch, corrupted JSON
- **Solution**: Check data format and structure

##### InternalError
- **Message**: "Internal error: {details}"
- **Description**: An unexpected internal error occurred
- **Common Causes**: Programming error, unexpected state
- **Solution**: Report to developers with error details

---

## Summary | 总结

This document provides comprehensive error documentation in Chinese and English for sa-token-rust. Each error includes:
- Error message
- Detailed description
- Common causes
- Solutions

For developers integrating sa-token-rust, this guide helps understand and handle errors effectively.

---

**Version**: 0.1.13  
**Last Updated**: 2025-01-15

