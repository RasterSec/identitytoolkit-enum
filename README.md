# Identity Toolkit API Enumerator

A security assessment tool for enumerating Google Identity Toolkit (Firebase Authentication / Identity Platform) API capabilities. Useful for penetration testing, bug bounty hunting, and security assessments of Firebase/GCP applications.

## Features

- **API Key Scope Analysis**: Determine what an exposed API key can access
- **Email Enumeration Detection**: Identify if the API allows email enumeration via multiple vectors
- **IdP Provider Discovery**: Detect which identity providers (Google, Facebook, GitHub, etc.) are enabled
- **Project & Tenant Discovery**: Auto-discover project IDs and tenant configurations
- **Authentication Testing**: Test various auth methods (password, phone, custom token, IdP)
- **MFA Status Detection**: Check if MFA endpoints are active
- **Configuration Extraction**: Extract password policies, reCAPTCHA settings, authorized domains

## Installation

```bash
go install github.com/RasterSec/identitytoolkit-enum@latest
```

Or build from source:

```bash
git clone https://github.com/RasterSec/identitytoolkit-enum.git
cd identitytoolkit-enum
go build -o identitytoolkit-enum .
```

## Usage

```bash
identitytoolkit-enum -key=<API_KEY> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-key` | API key (required) - also accepts full URL with `key=` parameter |
| `-email` | Email address to test for enumeration/auth |
| `-password` | Password to test with email |
| `-idtoken` | Firebase ID token for authenticated endpoint testing |
| `-bearer` | OAuth2 bearer token for admin endpoints |
| `-customtoken` | Custom token from Firebase Admin SDK |
| `-phone` | Phone number in E.164 format (+15551234567) |
| `-project` | Project ID (auto-discovered if not provided) |
| `-tenants` | Comma-separated tenant IDs (auto-discovered if not provided) |
| `-v` | Verbose output - show all API responses |

### Examples

```bash
# Basic scan with just API key
identitytoolkit-enum -key=AIzaSyD4...

# Test specific email for enumeration
identitytoolkit-enum -key=AIzaSyD4... -email=admin@target.com

# Test with credentials
identitytoolkit-enum -key=AIzaSyD4... -email=user@target.com -password=pass123

# Full scan with ID token (for authenticated endpoints)
identitytoolkit-enum -key=AIzaSyD4... -idtoken=eyJhbG...

# Specify project and tenants manually
identitytoolkit-enum -key=AIzaSyD4... -project=my-project -tenants=tenant1,tenant2

# Accept URL-style input
identitytoolkit-enum -key="https://identitytoolkit.googleapis.com/v1/projects?key=AIzaSyD4..."
```

## What It Checks

### Phase 1: Basic V1 API Endpoints
- `GET /v1/projects` - Project configuration, authorized domains
- `GET /v1/recaptchaParams` - reCAPTCHA site keys
- `GET /v1/publicKeys` - Token signing certificates
- `GET /v1/sessionCookiePublicKeys` - Session validation keys
- `POST /v1/accounts:signUp` - Anonymous/email signup availability
- `POST /v1/accounts:signInWithPassword` - Password auth & email enumeration
- `POST /v1/accounts:createAuthUri` - Email enumeration, provider discovery
- `POST /v1/accounts:sendOobCode` - Password reset, email link sign-in
- `POST /v1/accounts:signInWithCustomToken` - Custom token authentication
- `POST /v1/accounts:signInWithIdp` - Social provider authentication (Google, Facebook, Twitter, GitHub, Apple, Microsoft, Yahoo, LinkedIn)
- `POST /v1/accounts:sendVerificationCode` - Phone authentication

### Phase 2: V2 API Endpoints
- `GET /v2/passwordPolicy` - Password requirements
- `GET /v2/recaptchaConfig` - reCAPTCHA enforcement state (Web, Android, iOS)

### Phase 3: Project-scoped Endpoints
- `GET /v1/projects/{projectId}/accounts:batchGet` - Batch account retrieval
- `POST /v1/projects/{projectId}/accounts:lookup` - Account lookup by email
- `POST /v1/projects/{projectId}/accounts:query` - Query accounts
- `POST /v1/projects/{projectId}:createSessionCookie` - Session cookie creation
- `GET /v2/projects/{projectId}/config` - Full project configuration
- `GET /v2/projects/{projectId}/tenants` - List tenants
- `GET /v2/projects/{projectId}/oauthIdpConfigs` - OAuth provider configs
- `GET /v2/projects/{projectId}/inboundSamlConfigs` - SAML configs
- `GET /v2/projects/{projectId}/defaultSupportedIdpConfigs` - Default IdP configs

### Phase 4: Tenant-scoped Endpoints
Same as project-scoped but for each discovered tenant:
- `POST /v1/projects/{projectId}/tenants/{tenantId}/accounts:*`
- `GET /v2/projects/{projectId}/tenants/{tenantId}/*`

### Phase 5: MFA Endpoints
- `POST /v2/accounts/mfaEnrollment:start` - MFA enrollment
- `POST /v2/accounts/mfaSignIn:start` - MFA sign-in

### Phase 6: Token Endpoints
- `POST /v1/token` - Token refresh
- Token exchange operations

## Output Legend

| Status | Color | Meaning |
|--------|-------|---------|
| `[OK]` | Green | Endpoint accessible, data returned |
| `[400]` | Cyan | Endpoint exists but needs valid parameters |
| `[401]` | Yellow | Requires OAuth2 authentication |
| `[403]` | Red | Permission denied |
| `[404]` | Gray | Endpoint not found |
| `[SKIP]` | Yellow | Skipped (missing required token) |

### Security Notes Color Coding

- **Red**: Critical findings (anonymous signup, valid credentials)
- **Magenta**: Email enumeration vectors
- **Green**: Enabled features/providers
- **Blue**: Endpoints requiring idToken
- **Yellow**: General security observations

## Security Findings

The tool detects various security misconfigurations:

### Email Enumeration
- Different error messages for existing vs non-existing emails
- `createAuthUri` returns `registered: true/false`
- Password reset reveals email existence

### Misconfigured Authentication
- Anonymous signup enabled
- Weak password policies
- Missing reCAPTCHA enforcement
- Passwordless email link sign-in enabled

### Exposed Configuration
- Authorized domains leaked
- Project ID exposed
- IdP provider configuration visible
- Custom claims in tokens

### Token-based Access
With a valid `idToken`, additional data is exposed:
- Full user account information
- Custom claims (roles, permissions)
- Provider details
- Account modification capabilities

## Example Output

```
Identity Toolkit Enumerator - v1.0.0
https://www.rastersec.com
======================================================================
API Key: AIzaSyD4...WfYk
Test Email: test@test.com

[*] Phase 1: Basic V1 API Endpoints (no project ID required)
======================================================================
[+] Discovered Project ID: 265935561326

[OK  ] GET /v1/projects
       Response: {"authorizedDomains": ["localhost", "example.firebaseapp.com"], "projectId": "265735561316"}

[400 ] POST /v1/accounts:signInWithPassword
       Code: INVALID_PASSWORD
       >> Email 'test@test.com' EXISTS but wrong password - EMAIL ENUMERATION possible

[OK  ] POST /v1/accounts:createAuthUri
       >> Email 'test@test.com' is REGISTERED - EMAIL ENUMERATION confirmed

======================================================================
SUMMARY
======================================================================

Endpoint Stats:
  Successful (2xx): 11
  Bad Request (400): 19
  Unauthorized (401): 7
  Skipped: 3

Enabled IdP Providers: [twitter.com github.com microsoft.com]
Disabled IdP Providers: [google.com facebook.com apple.com]

[+] ENDPOINTS REQUIRING idToken:
    - POST /v1/accounts:lookup - REQUIRES_IDTOKEN: Returns full user account info
    - POST /v1/accounts:update - REQUIRES_IDTOKEN: Can modify user account

[!] EMAIL ENUMERATION VECTORS:
    - Email 'test@test.com' EXISTS but wrong password - EMAIL ENUMERATION possible
    - Email 'test@test.com' is REGISTERED - EMAIL ENUMERATION confirmed

[*] Discovered Configuration:
    Authorized Domains: [localhost example.firebaseapp.com]
    Project ID: 265935561326
    Password Policy: {minPasswordLength: 6, maxPasswordLength: 4096}
```

## Use Cases

1. **Penetration Testing**: Assess Firebase/Identity Platform security during authorized engagements
2. **Bug Bounty**: Identify misconfigurations in bug bounty targets
3. **Security Audits**: Verify proper API key restrictions and authentication settings
4. **Configuration Review**: Check for email enumeration, weak policies, exposed endpoints

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing any systems you do not own. The authors are not responsible for misuse of this tool.

## License

MIT License

## Contributing

Contributions welcome! Please submit issues and pull requests on GitHub.

## References

- [Google Identity Toolkit API Documentation](https://cloud.google.com/identity-platform/docs/reference/rest)
- [Firebase Authentication REST API](https://firebase.google.com/docs/reference/rest/auth)
