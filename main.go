package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	baseURL = "https://identitytoolkit.googleapis.com"
)

type Config struct {
	APIKey      string
	IDToken     string
	BearerToken string
	Email       string
	Password    string
	CustomToken string
	Phone       string
	Verbose     bool
	ProjectID   string   // Discovered or provided
	TenantIDs   []string // Discovered or provided
}

type EndpointResult struct {
	Endpoint     string
	Method       string
	StatusCode   int
	Success      bool
	Response     interface{}
	Error        string
	ErrorCode    string
	SecurityNote string
}

type Checker struct {
	config *Config
	client *http.Client
}

func NewChecker(config *Config) *Checker {
	return &Checker{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Checker) makeRequest(method, endpoint string, body interface{}, requiresIDToken, requiresBearer bool) *EndpointResult {
	result := &EndpointResult{
		Endpoint: endpoint,
		Method:   method,
	}

	// Skip if tokens required but not provided
	if requiresIDToken && c.config.IDToken == "" {
		result.Error = "skipped: requires idToken"
		return result
	}
	if requiresBearer && c.config.BearerToken == "" {
		result.Error = "skipped: requires bearer token"
		return result
	}

	url := fmt.Sprintf("%s%s", baseURL, endpoint)
	if strings.Contains(endpoint, "?") {
		url += "&key=" + c.config.APIKey
	} else {
		url += "?key=" + c.config.APIKey
	}

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			result.Error = fmt.Sprintf("failed to marshal body: %v", err)
			return result
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}

	req.Header.Set("Content-Type", "application/json")

	if c.config.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.BearerToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read response: %v", err)
		return result
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		result.Response = string(respBody)
	} else {
		result.Response = jsonResp
		// Extract error code for analysis
		if errObj, ok := jsonResp["error"].(map[string]interface{}); ok {
			if msg, ok := errObj["message"].(string); ok {
				result.ErrorCode = msg
			}
		}
	}

	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 300

	return result
}

// discoverProjectID attempts to get the project ID from /v1/projects
func (c *Checker) discoverProjectID() string {
	result := c.makeRequest("GET", "/v1/projects", nil, false, false)
	if result.Success {
		if resp, ok := result.Response.(map[string]interface{}); ok {
			if projectId, ok := resp["projectId"].(string); ok {
				return projectId
			}
		}
	}
	return ""
}

// discoverTenants attempts to list tenants for a project
func (c *Checker) discoverTenants(projectID string) []string {
	var tenants []string

	// Try V2 endpoint to list tenants
	endpoint := fmt.Sprintf("/v2/projects/%s/tenants", projectID)
	result := c.makeRequest("GET", endpoint, nil, false, false)

	if result.Success {
		if resp, ok := result.Response.(map[string]interface{}); ok {
			if tenantList, ok := resp["tenants"].([]interface{}); ok {
				for _, t := range tenantList {
					if tenant, ok := t.(map[string]interface{}); ok {
						if name, ok := tenant["name"].(string); ok {
							// Extract tenant ID from name like "projects/xxx/tenants/tenant-id"
							parts := strings.Split(name, "/")
							if len(parts) >= 4 {
								tenants = append(tenants, parts[len(parts)-1])
							}
						}
					}
				}
			}
		}
	}

	return tenants
}

func (c *Checker) CheckAll() []*EndpointResult {
	var results []*EndpointResult

	fmt.Println("\n[*] Phase 1: Basic V1 API Endpoints (no project ID required)")
	fmt.Println(strings.Repeat("=", 70))

	// V1 - Get Project Config (also extracts projectId)
	projectResult := c.makeRequest("GET", "/v1/projects", nil, false, false)
	results = append(results, projectResult)

	// Extract projectId for later use
	if c.config.ProjectID == "" && projectResult.Success {
		if resp, ok := projectResult.Response.(map[string]interface{}); ok {
			if projectId, ok := resp["projectId"].(string); ok {
				c.config.ProjectID = projectId
				fmt.Printf("[+] Discovered Project ID: %s\n", projectId)
			}
		}
	}

	// V1 - Get reCAPTCHA Params
	results = append(results, c.makeRequest("GET", "/v1/recaptchaParams", nil, false, false))

	// V1 - Get Public Keys
	results = append(results, c.makeRequest("GET", "/v1/publicKeys", nil, false, false))

	// V1 - Get Session Cookie Public Keys
	results = append(results, c.makeRequest("GET", "/v1/sessionCookiePublicKeys", nil, false, false))

	// V1 - Sign Up - Test anonymous signup
	signUpResult := c.makeRequest("POST", "/v1/accounts:signUp", map[string]interface{}{
		"returnSecureToken": true,
	}, false, false)
	c.analyzeSignUpResult(signUpResult)
	results = append(results, signUpResult)

	// V1 - Sign Up with email if provided
	if c.config.Email != "" {
		emailSignUpResult := c.makeRequest("POST", "/v1/accounts:signUp", map[string]interface{}{
			"email":             c.config.Email,
			"password":          c.config.Password,
			"returnSecureToken": true,
		}, false, false)
		emailSignUpResult.Endpoint = "/v1/accounts:signUp (email)"
		c.analyzeEmailSignUpResult(emailSignUpResult)
		results = append(results, emailSignUpResult)
	}

	// V1 - Sign In with Password
	testEmail := "test@example.com"
	if c.config.Email != "" {
		testEmail = c.config.Email
	}
	testPassword := "TestPassword123!"
	if c.config.Password != "" {
		testPassword = c.config.Password
	}

	signInResult := c.makeRequest("POST", "/v1/accounts:signInWithPassword", map[string]interface{}{
		"email":             testEmail,
		"password":          testPassword,
		"returnSecureToken": true,
	}, false, false)
	c.analyzeSignInResult(signInResult, testEmail)
	results = append(results, signInResult)

	// V1 - Email enumeration check via createAuthUri
	authUriResult := c.makeRequest("POST", "/v1/accounts:createAuthUri", map[string]interface{}{
		"identifier":  testEmail,
		"continueUri": "http://localhost",
	}, false, false)
	c.analyzeAuthUriResult(authUriResult, testEmail)
	results = append(results, authUriResult)

	// V1 - Send OOB Code (password reset)
	oobResult := c.makeRequest("POST", "/v1/accounts:sendOobCode", map[string]interface{}{
		"requestType": "PASSWORD_RESET",
		"email":       testEmail,
	}, false, false)
	c.analyzeOobResult(oobResult)
	results = append(results, oobResult)

	// V1 - Email link sign-in
	emailLinkResult := c.makeRequest("POST", "/v1/accounts:sendOobCode", map[string]interface{}{
		"requestType": "EMAIL_SIGNIN",
		"email":       testEmail,
	}, false, false)
	emailLinkResult.Endpoint = "/v1/accounts:sendOobCode (EMAIL_SIGNIN)"
	c.analyzeEmailLinkResult(emailLinkResult)
	results = append(results, emailLinkResult)

	// V1 - Sign In with Custom Token
	customToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ.test"
	if c.config.CustomToken != "" {
		customToken = c.config.CustomToken
	}
	customTokenResult := c.makeRequest("POST", "/v1/accounts:signInWithCustomToken", map[string]interface{}{
		"token":             customToken,
		"returnSecureToken": true,
	}, false, false)
	c.analyzeCustomTokenResult(customTokenResult)
	results = append(results, customTokenResult)

	// V1 - Sign In with IdP - test various providers
	providers := []string{"google.com", "facebook.com", "twitter.com", "github.com", "apple.com", "microsoft.com", "yahoo.com", "linkedin.com"}
	for _, provider := range providers {
		idpResult := c.makeRequest("POST", "/v1/accounts:signInWithIdp", map[string]interface{}{
			"requestUri":          "http://localhost",
			"postBody":            fmt.Sprintf("id_token=test&providerId=%s", provider),
			"returnSecureToken":   true,
			"returnIdpCredential": true,
		}, false, false)
		idpResult.Endpoint = fmt.Sprintf("/v1/accounts:signInWithIdp (%s)", provider)
		c.analyzeIdpResult(idpResult, provider)
		results = append(results, idpResult)
	}

	// V1 - Phone auth - send verification code
	testPhone := "+15555555555"
	if c.config.Phone != "" {
		testPhone = c.config.Phone
	}
	phoneResult := c.makeRequest("POST", "/v1/accounts:sendVerificationCode", map[string]interface{}{
		"phoneNumber": testPhone,
	}, false, false)
	c.analyzePhoneResult(phoneResult)
	results = append(results, phoneResult)

	// Endpoints requiring idToken
	if c.config.IDToken != "" {
		fmt.Println("\n[*] Checking Authenticated Endpoints (idToken)...")
		fmt.Println(strings.Repeat("=", 70))

		// Account lookup - get user info
		lookupResult := c.makeRequest("POST", "/v1/accounts:lookup", map[string]interface{}{
			"idToken": c.config.IDToken,
		}, false, false)
		if lookupResult.Success {
			lookupResult.SecurityNote = "IDTOKEN_REQUIRED: Retrieved full user account info"
		}
		results = append(results, lookupResult)

		// Account update - test if we can modify
		updateResult := c.makeRequest("POST", "/v1/accounts:update", map[string]interface{}{
			"idToken": c.config.IDToken,
		}, false, false)
		if updateResult.Success {
			updateResult.SecurityNote = "IDTOKEN_REQUIRED: Can modify user account"
		}
		results = append(results, updateResult)

		// Send email verification
		verifyResult := c.makeRequest("POST", "/v1/accounts:sendOobCode", map[string]interface{}{
			"idToken":     c.config.IDToken,
			"requestType": "VERIFY_EMAIL",
		}, false, false)
		verifyResult.Endpoint = "/v1/accounts:sendOobCode (VERIFY_EMAIL with idToken)"
		if verifyResult.Success {
			verifyResult.SecurityNote = "IDTOKEN_REQUIRED: Can send email verification"
		}
		results = append(results, verifyResult)

		// Get fresh tokens
		refreshResult := c.makeRequest("POST", "/v1/accounts:lookup", map[string]interface{}{
			"idToken": c.config.IDToken,
		}, false, false)
		refreshResult.Endpoint = "/v1/accounts:lookup (get user details)"
		results = append(results, refreshResult)

		// Link with email/password (test)
		linkResult := c.makeRequest("POST", "/v1/accounts:update", map[string]interface{}{
			"idToken": c.config.IDToken,
		}, false, false)
		linkResult.Endpoint = "/v1/accounts:update (link/unlink providers)"
		if linkResult.Success {
			linkResult.SecurityNote = "IDTOKEN_REQUIRED: Can link/unlink auth providers"
		}
		results = append(results, linkResult)
	} else {
		results = append(results, &EndpointResult{
			Endpoint:     "/v1/accounts:lookup",
			Method:       "POST",
			Error:        "skipped: requires idToken",
			SecurityNote: "REQUIRES_IDTOKEN: Returns full user account info, custom claims, provider details",
		})
		results = append(results, &EndpointResult{
			Endpoint:     "/v1/accounts:update",
			Method:       "POST",
			Error:        "skipped: requires idToken",
			SecurityNote: "REQUIRES_IDTOKEN: Can modify user account, change email, link providers",
		})
		results = append(results, &EndpointResult{
			Endpoint:     "/v1/accounts:delete",
			Method:       "POST",
			Error:        "skipped: requires idToken",
			SecurityNote: "REQUIRES_IDTOKEN: Can delete the authenticated user's account",
		})
	}

	fmt.Println("\n[*] Phase 2: V2 API Endpoints")
	fmt.Println(strings.Repeat("=", 70))

	// V2 - Get Password Policy
	results = append(results, c.makeRequest("GET", "/v2/passwordPolicy", nil, false, false))

	// V2 - Get reCAPTCHA Config for each client type
	clientTypes := []string{"CLIENT_TYPE_WEB", "CLIENT_TYPE_ANDROID", "CLIENT_TYPE_IOS"}
	for _, clientType := range clientTypes {
		recaptchaResult := c.makeRequest("GET", fmt.Sprintf("/v2/recaptchaConfig?clientType=%s&version=RECAPTCHA_ENTERPRISE", clientType), nil, false, false)
		recaptchaResult.Endpoint = fmt.Sprintf("/v2/recaptchaConfig (%s)", clientType)
		results = append(results, recaptchaResult)
	}

	// Project-scoped endpoints (require projectId)
	if c.config.ProjectID != "" {
		fmt.Printf("\n[*] Phase 3: Project-scoped Endpoints (Project: %s)\n", c.config.ProjectID)
		fmt.Println(strings.Repeat("=", 70))

		projectID := c.config.ProjectID

		// V1 Project endpoints
		v1ProjectEndpoints := []struct {
			method   string
			endpoint string
			body     map[string]interface{}
			desc     string
		}{
			{"GET", fmt.Sprintf("/v1/projects/%s/accounts:batchGet", projectID), nil, "Batch get accounts"},
			{"POST", fmt.Sprintf("/v1/projects/%s/accounts:lookup", projectID), map[string]interface{}{"email": []string{testEmail}}, "Lookup account by email"},
			{"POST", fmt.Sprintf("/v1/projects/%s/accounts:query", projectID), map[string]interface{}{"returnUserInfo": true, "limit": 1}, "Query accounts"},
			{"POST", fmt.Sprintf("/v1/projects/%s/accounts:signUp", projectID), map[string]interface{}{"returnSecureToken": true}, "Anonymous signup (project-scoped)"},
			{"POST", fmt.Sprintf("/v1/projects/%s/accounts:sendOobCode", projectID), map[string]interface{}{"requestType": "PASSWORD_RESET", "email": testEmail}, "Send OOB code (project-scoped)"},
			{"POST", fmt.Sprintf("/v1/projects/%s:createSessionCookie", projectID), map[string]interface{}{"idToken": "test", "validDuration": "3600s"}, "Create session cookie"},
			{"POST", fmt.Sprintf("/v1/projects/%s:queryAccounts", projectID), map[string]interface{}{"returnUserInfo": true, "limit": 1}, "Query accounts (alt)"},
		}

		for _, ep := range v1ProjectEndpoints {
			result := c.makeRequest(ep.method, ep.endpoint, ep.body, false, false)
			c.analyzeProjectEndpoint(result, ep.desc)
			results = append(results, result)
		}

		// V2 Project endpoints
		fmt.Println("\n[*] V2 Project Configuration Endpoints")
		fmt.Println(strings.Repeat("-", 50))

		v2ProjectEndpoints := []struct {
			method   string
			endpoint string
			desc     string
		}{
			{"GET", fmt.Sprintf("/v2/projects/%s/config", projectID), "Get project config"},
			{"GET", fmt.Sprintf("/v2/projects/%s/tenants", projectID), "List tenants"},
			{"GET", fmt.Sprintf("/v2/projects/%s/oauthIdpConfigs", projectID), "List OAuth IdP configs"},
			{"GET", fmt.Sprintf("/v2/projects/%s/inboundSamlConfigs", projectID), "List SAML configs"},
			{"GET", fmt.Sprintf("/v2/projects/%s/defaultSupportedIdpConfigs", projectID), "List default IdP configs"},
		}

		for _, ep := range v2ProjectEndpoints {
			result := c.makeRequest(ep.method, ep.endpoint, nil, false, false)
			c.analyzeProjectEndpoint(result, ep.desc)
			results = append(results, result)

			// Extract tenants if listing tenants endpoint
			if strings.Contains(ep.endpoint, "/tenants") && result.Success {
				if resp, ok := result.Response.(map[string]interface{}); ok {
					if tenantList, ok := resp["tenants"].([]interface{}); ok {
						for _, t := range tenantList {
							if tenant, ok := t.(map[string]interface{}); ok {
								if name, ok := tenant["name"].(string); ok {
									parts := strings.Split(name, "/")
									if len(parts) >= 4 {
										tenantID := parts[len(parts)-1]
										c.config.TenantIDs = append(c.config.TenantIDs, tenantID)
										fmt.Printf("[+] Discovered Tenant: %s\n", tenantID)
									}
								}
							}
						}
					}
				}
			}
		}

		// Admin/v2 endpoints with bearer token
		if c.config.BearerToken != "" {
			fmt.Println("\n[*] Admin V2 Endpoints (Bearer Token)")
			fmt.Println(strings.Repeat("-", 50))

			adminEndpoints := []struct {
				method   string
				endpoint string
				desc     string
			}{
				{"GET", fmt.Sprintf("/admin/v2/projects/%s/config", projectID), "Admin config (v2)"},
			}

			for _, ep := range adminEndpoints {
				result := c.makeRequest(ep.method, ep.endpoint, nil, false, true)
				c.analyzeProjectEndpoint(result, ep.desc)
				results = append(results, result)
			}
		}
	}

	// Tenant-scoped endpoints
	if c.config.ProjectID != "" && len(c.config.TenantIDs) > 0 {
		fmt.Printf("\n[*] Phase 4: Tenant-scoped Endpoints (%d tenants found)\n", len(c.config.TenantIDs))
		fmt.Println(strings.Repeat("=", 70))

		projectID := c.config.ProjectID

		for _, tenantID := range c.config.TenantIDs {
			fmt.Printf("\n[*] Testing Tenant: %s\n", tenantID)
			fmt.Println(strings.Repeat("-", 50))

			// V1 Tenant endpoints
			v1TenantEndpoints := []struct {
				method   string
				endpoint string
				body     map[string]interface{}
				desc     string
			}{
				{"GET", fmt.Sprintf("/v1/projects/%s/tenants/%s/accounts:batchGet", projectID, tenantID), nil, "Batch get tenant accounts"},
				{"POST", fmt.Sprintf("/v1/projects/%s/tenants/%s/accounts:lookup", projectID, tenantID), map[string]interface{}{"email": []string{testEmail}}, "Lookup tenant account"},
				{"POST", fmt.Sprintf("/v1/projects/%s/tenants/%s/accounts:query", projectID, tenantID), map[string]interface{}{"returnUserInfo": true, "limit": 1}, "Query tenant accounts"},
				{"POST", fmt.Sprintf("/v1/projects/%s/tenants/%s/accounts:signUp", projectID, tenantID), map[string]interface{}{"returnSecureToken": true}, "Tenant anonymous signup"},
				{"POST", fmt.Sprintf("/v1/projects/%s/tenants/%s/accounts:signInWithPassword", projectID, tenantID), map[string]interface{}{"email": testEmail, "password": testPassword, "returnSecureToken": true}, "Tenant signIn"},
				{"POST", fmt.Sprintf("/v1/projects/%s/tenants/%s/accounts:sendOobCode", projectID, tenantID), map[string]interface{}{"requestType": "PASSWORD_RESET", "email": testEmail}, "Tenant password reset"},
				{"POST", fmt.Sprintf("/v1/projects/%s/tenants/%s:createSessionCookie", projectID, tenantID), map[string]interface{}{"idToken": "test", "validDuration": "3600s"}, "Tenant session cookie"},
			}

			for _, ep := range v1TenantEndpoints {
				result := c.makeRequest(ep.method, ep.endpoint, ep.body, false, false)
				c.analyzeTenantEndpoint(result, ep.desc, tenantID)
				results = append(results, result)
			}

			// V2 Tenant endpoints
			v2TenantEndpoints := []struct {
				method   string
				endpoint string
				desc     string
			}{
				{"GET", fmt.Sprintf("/v2/projects/%s/tenants/%s", projectID, tenantID), "Get tenant config"},
				{"GET", fmt.Sprintf("/v2/projects/%s/tenants/%s/oauthIdpConfigs", projectID, tenantID), "Tenant OAuth IdPs"},
				{"GET", fmt.Sprintf("/v2/projects/%s/tenants/%s/inboundSamlConfigs", projectID, tenantID), "Tenant SAML configs"},
				{"GET", fmt.Sprintf("/v2/projects/%s/tenants/%s/defaultSupportedIdpConfigs", projectID, tenantID), "Tenant default IdPs"},
			}

			for _, ep := range v2TenantEndpoints {
				result := c.makeRequest(ep.method, ep.endpoint, nil, false, false)
				c.analyzeTenantEndpoint(result, ep.desc, tenantID)
				results = append(results, result)
			}
		}
	} else if c.config.ProjectID != "" {
		fmt.Println("\n[*] Phase 4: No tenants discovered, skipping tenant-scoped endpoints")
	}

	// MFA endpoints
	fmt.Println("\n[*] Phase 5: MFA Endpoints")
	fmt.Println(strings.Repeat("=", 70))

	mfaEndpoints := []struct {
		method   string
		endpoint string
		body     map[string]interface{}
		desc     string
	}{
		{"POST", "/v2/accounts/mfaEnrollment:start", map[string]interface{}{"idToken": "test", "phoneEnrollmentInfo": map[string]interface{}{"phoneNumber": testPhone}}, "MFA enrollment start"},
		{"POST", "/v2/accounts/mfaSignIn:start", map[string]interface{}{"mfaPendingCredential": "test"}, "MFA sign-in start"},
	}

	for _, ep := range mfaEndpoints {
		result := c.makeRequest(ep.method, ep.endpoint, ep.body, false, false)
		c.analyzeMfaEndpoint(result, ep.desc)
		results = append(results, result)
	}

	// Token endpoints
	fmt.Println("\n[*] Phase 6: Token Endpoints")
	fmt.Println(strings.Repeat("=", 70))

	// SecureToken endpoint for token refresh
	tokenResult := c.makeRequest("POST", "/v1/token", map[string]interface{}{
		"grant_type":    "refresh_token",
		"refresh_token": "test_refresh_token",
	}, false, false)
	tokenResult.Endpoint = "/v1/token (refresh)"
	results = append(results, tokenResult)

	// Token exchange
	exchangeResult := c.makeRequest("POST", "/v1/accounts:signInWithIdp", map[string]interface{}{
		"requestUri":        "http://localhost",
		"returnSecureToken": true,
	}, false, false)
	exchangeResult.Endpoint = "/v1/accounts:signInWithIdp (token exchange)"
	results = append(results, exchangeResult)

	return results
}

func (c *Checker) analyzeSignUpResult(result *EndpointResult) {
	switch result.ErrorCode {
	case "ADMIN_ONLY_OPERATION":
		result.SecurityNote = "Anonymous signup DISABLED - requires admin or email/password"
	case "OPERATION_NOT_ALLOWED":
		result.SecurityNote = "Signup DISABLED entirely"
	case "":
		if result.Success {
			result.SecurityNote = "CRITICAL: Anonymous signup ENABLED - can create accounts without email!"
		}
	}
}

func (c *Checker) analyzeEmailSignUpResult(result *EndpointResult) {
	switch result.ErrorCode {
	case "EMAIL_EXISTS":
		result.SecurityNote = "Email already registered - EMAIL ENUMERATION possible"
	case "WEAK_PASSWORD":
		result.SecurityNote = "Email signup enabled but password too weak"
	case "INVALID_EMAIL":
		result.SecurityNote = "Email signup enabled"
	case "OPERATION_NOT_ALLOWED":
		result.SecurityNote = "Email/password signup DISABLED"
	case "":
		if result.Success {
			result.SecurityNote = "CRITICAL: Created new account successfully!"
		}
	}
}

func (c *Checker) analyzeSignInResult(result *EndpointResult, email string) {
	switch {
	case strings.Contains(result.ErrorCode, "EMAIL_NOT_FOUND"):
		result.SecurityNote = fmt.Sprintf("Email '%s' NOT registered - EMAIL ENUMERATION possible", email)
	case strings.Contains(result.ErrorCode, "INVALID_PASSWORD"):
		result.SecurityNote = fmt.Sprintf("Email '%s' EXISTS but wrong password - EMAIL ENUMERATION possible", email)
	case strings.Contains(result.ErrorCode, "USER_DISABLED"):
		result.SecurityNote = fmt.Sprintf("Email '%s' EXISTS but account disabled", email)
	case strings.Contains(result.ErrorCode, "TOO_MANY_ATTEMPTS"):
		result.SecurityNote = "Rate limiting active"
	case result.Success:
		result.SecurityNote = "CRITICAL: Valid credentials - obtained idToken!"
	}
}

func (c *Checker) analyzeAuthUriResult(result *EndpointResult, email string) {
	if resp, ok := result.Response.(map[string]interface{}); ok {
		if registered, ok := resp["registered"].(bool); ok {
			if registered {
				result.SecurityNote = fmt.Sprintf("Email '%s' is REGISTERED - EMAIL ENUMERATION confirmed", email)
			} else {
				result.SecurityNote = fmt.Sprintf("Email '%s' is NOT registered", email)
			}
		}
		if providers, ok := resp["allProviders"].([]interface{}); ok && len(providers) > 0 {
			result.SecurityNote += fmt.Sprintf(" | Providers: %v", providers)
		}
		if signinMethods, ok := resp["signinMethods"].([]interface{}); ok && len(signinMethods) > 0 {
			result.SecurityNote += fmt.Sprintf(" | SignIn methods: %v", signinMethods)
		}
	}
}

func (c *Checker) analyzeOobResult(result *EndpointResult) {
	if result.Success {
		result.SecurityNote = "Password reset emails can be sent to ANY email"
	} else if strings.Contains(result.ErrorCode, "EMAIL_NOT_FOUND") {
		result.SecurityNote = "Password reset reveals email existence - EMAIL ENUMERATION"
	}
}

func (c *Checker) analyzeEmailLinkResult(result *EndpointResult) {
	if result.Success {
		result.SecurityNote = "Email link (passwordless) sign-in ENABLED"
	} else if strings.Contains(result.ErrorCode, "OPERATION_NOT_ALLOWED") {
		result.SecurityNote = "Email link sign-in DISABLED"
	} else if strings.Contains(result.ErrorCode, "EMAIL_NOT_FOUND") {
		result.SecurityNote = "Email link enabled but email not found - EMAIL ENUMERATION"
	}
}

func (c *Checker) analyzeCustomTokenResult(result *EndpointResult) {
	switch {
	case strings.Contains(result.ErrorCode, "INVALID_CUSTOM_TOKEN"):
		result.SecurityNote = "Custom token auth ENABLED but token invalid"
	case strings.Contains(result.ErrorCode, "CREDENTIAL_MISMATCH"):
		result.SecurityNote = "Custom token auth ENABLED but wrong project"
	case strings.Contains(result.ErrorCode, "MISSING_IDENTIFIER"):
		result.SecurityNote = "Custom token auth ENABLED (malformed token)"
	case strings.Contains(result.ErrorCode, "INVALID_IDENTIFIER"):
		result.SecurityNote = "Custom token auth ENABLED (invalid format)"
	case result.Success:
		result.SecurityNote = "CRITICAL: Custom token accepted!"
	}
}

func (c *Checker) analyzeIdpResult(result *EndpointResult, provider string) {
	switch {
	case strings.Contains(result.ErrorCode, "OPERATION_NOT_ALLOWED"):
		// Definitive - provider is not enabled in Firebase Console
		result.SecurityNote = fmt.Sprintf("Provider '%s' NOT configured", provider)
	case strings.Contains(result.ErrorCode, "INVALID_IDP_RESPONSE"):
		// Provider validated the request but token was invalid - likely enabled
		result.SecurityNote = fmt.Sprintf("Provider '%s' likely ENABLED (invalid token)", provider)
	case strings.Contains(result.ErrorCode, "INVALID_CREDENTIAL_OR_PROVIDER_ID"):
		// Ambiguous - credential format rejected before config check
		// Cannot determine if provider is enabled or not
		result.SecurityNote = fmt.Sprintf("Provider '%s' status UNKNOWN (credential rejected before config check)", provider)
	case result.Success:
		result.SecurityNote = fmt.Sprintf("CRITICAL: Authenticated with %s!", provider)
	}
}

func (c *Checker) analyzePhoneResult(result *EndpointResult) {
	switch {
	case strings.Contains(result.ErrorCode, "OPERATION_NOT_ALLOWED"):
		result.SecurityNote = "Phone auth DISABLED"
	case strings.Contains(result.ErrorCode, "INVALID_PHONE_NUMBER"):
		result.SecurityNote = "Phone auth ENABLED (invalid number format)"
	case strings.Contains(result.ErrorCode, "TOO_MANY_ATTEMPTS"):
		result.SecurityNote = "Phone auth ENABLED but rate limited"
	case strings.Contains(result.ErrorCode, "CAPTCHA_CHECK_FAILED"):
		result.SecurityNote = "Phone auth ENABLED (requires reCAPTCHA)"
	case strings.Contains(result.ErrorCode, "MISSING_RECAPTCHA_TOKEN"):
		result.SecurityNote = "Phone auth ENABLED (requires reCAPTCHA token)"
	case result.Success:
		result.SecurityNote = "Phone auth ENABLED - verification code sent!"
	}
}

func (c *Checker) analyzeProjectEndpoint(result *EndpointResult, desc string) {
	switch {
	case result.Success:
		result.SecurityNote = fmt.Sprintf("ACCESSIBLE: %s", desc)
	case result.StatusCode == 401:
		result.SecurityNote = "Requires authentication"
	case result.StatusCode == 403:
		result.SecurityNote = "Permission denied - requires higher privileges"
	case result.StatusCode == 400:
		if strings.Contains(result.ErrorCode, "INVALID_PROJECT_ID") {
			result.SecurityNote = "Invalid project ID format"
		} else if strings.Contains(result.ErrorCode, "PROJECT_NOT_FOUND") {
			result.SecurityNote = "Project not found or no access"
		} else {
			result.SecurityNote = fmt.Sprintf("Endpoint exists: %s (bad request)", desc)
		}
	}
}

func (c *Checker) analyzeTenantEndpoint(result *EndpointResult, desc string, tenantID string) {
	switch {
	case result.Success:
		result.SecurityNote = fmt.Sprintf("ACCESSIBLE [%s]: %s", tenantID, desc)
	case result.StatusCode == 401:
		result.SecurityNote = fmt.Sprintf("[%s] Requires authentication", tenantID)
	case result.StatusCode == 403:
		result.SecurityNote = fmt.Sprintf("[%s] Permission denied", tenantID)
	case result.StatusCode == 400:
		if strings.Contains(result.ErrorCode, "TENANT_NOT_FOUND") {
			result.SecurityNote = fmt.Sprintf("[%s] Tenant not found", tenantID)
		} else if strings.Contains(result.ErrorCode, "ADMIN_ONLY_OPERATION") {
			result.SecurityNote = fmt.Sprintf("[%s] %s - admin only", tenantID, desc)
		} else {
			result.SecurityNote = fmt.Sprintf("[%s] Endpoint exists (bad request)", tenantID)
		}
	}
}

func (c *Checker) analyzeMfaEndpoint(result *EndpointResult, desc string) {
	switch {
	case strings.Contains(result.ErrorCode, "INVALID_ID_TOKEN"):
		result.SecurityNote = fmt.Sprintf("MFA endpoint active: %s (requires valid idToken)", desc)
	case strings.Contains(result.ErrorCode, "OPERATION_NOT_ALLOWED"):
		result.SecurityNote = "MFA DISABLED for this project"
	case strings.Contains(result.ErrorCode, "MFA_ENROLLMENT_NOT_FOUND"):
		result.SecurityNote = "MFA enabled but no enrollment found"
	case result.Success:
		result.SecurityNote = fmt.Sprintf("CRITICAL: MFA %s succeeded!", desc)
	default:
		if result.StatusCode == 400 {
			result.SecurityNote = fmt.Sprintf("MFA endpoint exists: %s", desc)
		}
	}
}

func printResult(result *EndpointResult, verbose bool) {
	var status string
	var color string

	if result.Error != "" && strings.HasPrefix(result.Error, "skipped") {
		status = "SKIP"
		color = "\033[33m" // Yellow
	} else if result.Success {
		status = "OK"
		color = "\033[32m" // Green
	} else if result.StatusCode == 400 {
		status = "400"
		color = "\033[36m" // Cyan
	} else if result.StatusCode == 401 {
		status = "401"
		color = "\033[33m" // Yellow
	} else if result.StatusCode == 403 {
		status = "403"
		color = "\033[31m" // Red
	} else if result.StatusCode == 404 {
		status = "404"
		color = "\033[90m" // Gray
	} else {
		status = fmt.Sprintf("%d", result.StatusCode)
		color = "\033[33m" // Yellow
	}

	reset := "\033[0m"

	fmt.Printf("%s[%-4s]%s %s %s\n", color, status, reset, result.Method, result.Endpoint)

	if result.Error != "" {
		fmt.Printf("       Error: %s\n", result.Error)
	}

	if result.ErrorCode != "" && !result.Success {
		fmt.Printf("       Code: %s\n", result.ErrorCode)
	}

	if result.SecurityNote != "" {
		noteColor := "\033[33m" // Yellow
		if strings.Contains(result.SecurityNote, "CRITICAL") || strings.Contains(result.SecurityNote, "ACCESSIBLE") {
			noteColor = "\033[31m" // Red for critical
		} else if strings.Contains(result.SecurityNote, "ENUMERATION") {
			noteColor = "\033[35m" // Magenta for enumeration
		} else if strings.Contains(result.SecurityNote, "ENABLED") {
			noteColor = "\033[32m" // Green for enabled
		} else if strings.Contains(result.SecurityNote, "IDTOKEN_REQUIRED") || strings.Contains(result.SecurityNote, "REQUIRES_IDTOKEN") {
			noteColor = "\033[34m" // Blue for idToken required
		}
		fmt.Printf("       %s>> %s%s\n", noteColor, result.SecurityNote, reset)
	}

	if verbose && result.Response != nil {
		jsonBytes, _ := json.MarshalIndent(result.Response, "       ", "  ")
		fmt.Printf("       Response:\n       %s\n", string(jsonBytes))
	} else if result.Success && result.Response != nil && !strings.Contains(result.Endpoint, "publicKeys") && !strings.Contains(result.Endpoint, "sessionCookiePublicKeys") {
		jsonBytes, _ := json.MarshalIndent(result.Response, "       ", "  ")
		responseStr := string(jsonBytes)
		// Truncate long responses
		if len(responseStr) > 1000 {
			responseStr = responseStr[:1000] + "\n       ... (truncated)"
		}
		fmt.Printf("       Response:\n       %s\n", responseStr)
	}
}

func printSummary(results []*EndpointResult) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("SUMMARY")
	fmt.Println(strings.Repeat("=", 70))

	var accessible, denied, unauthorized, badRequest, skipped, notFound int
	var criticalFindings []string
	var enumFindings []string
	var enabledProviders []string
	var disabledProviders []string
	var unknownProviders []string
	var accessibleEndpoints []string
	var idTokenEndpoints []string

	for _, r := range results {
		if r.Error != "" && strings.HasPrefix(r.Error, "skipped") {
			skipped++
			// Still collect idToken requirements for skipped entries
			if strings.Contains(r.SecurityNote, "REQUIRES_IDTOKEN") {
				idTokenEndpoints = append(idTokenEndpoints, fmt.Sprintf("%s %s - %s", r.Method, r.Endpoint, r.SecurityNote))
			}
			continue
		}
		switch {
		case r.Success:
			accessible++
			if strings.Contains(r.SecurityNote, "ACCESSIBLE") {
				accessibleEndpoints = append(accessibleEndpoints, r.Endpoint)
			}
		case r.StatusCode == 400:
			badRequest++
			if strings.Contains(r.Endpoint, "signInWithIdp") {
				provider := extractProvider(r.Endpoint)
				if strings.Contains(r.SecurityNote, "likely ENABLED") {
					enabledProviders = append(enabledProviders, provider)
				} else if strings.Contains(r.SecurityNote, "NOT configured") {
					disabledProviders = append(disabledProviders, provider)
				} else if strings.Contains(r.SecurityNote, "UNKNOWN") {
					unknownProviders = append(unknownProviders, provider)
				}
			}
		case r.StatusCode == 401:
			unauthorized++
		case r.StatusCode == 403:
			denied++
		case r.StatusCode == 404:
			notFound++
		}

		// Collect findings
		if strings.Contains(r.SecurityNote, "CRITICAL") {
			criticalFindings = append(criticalFindings, r.SecurityNote)
		}
		if strings.Contains(r.SecurityNote, "ENUMERATION") {
			enumFindings = append(enumFindings, r.SecurityNote)
		}
		if strings.Contains(r.SecurityNote, "IDTOKEN_REQUIRED") || strings.Contains(r.SecurityNote, "REQUIRES_IDTOKEN") {
			idTokenEndpoints = append(idTokenEndpoints, fmt.Sprintf("%s %s - %s", r.Method, r.Endpoint, r.SecurityNote))
		}
	}

	fmt.Printf("\nEndpoint Stats:\n")
	fmt.Printf("  Successful (2xx): %d\n", accessible)
	fmt.Printf("  Bad Request (400): %d\n", badRequest)
	fmt.Printf("  Unauthorized (401): %d\n", unauthorized)
	fmt.Printf("  Forbidden (403): %d\n", denied)
	fmt.Printf("  Not Found (404): %d\n", notFound)
	fmt.Printf("  Skipped: %d\n", skipped)

	if len(enabledProviders) > 0 {
		fmt.Printf("\n\033[32mEnabled IdP Providers:\033[0m %v\n", enabledProviders)
	}
	if len(disabledProviders) > 0 {
		fmt.Printf("\033[31mDisabled IdP Providers:\033[0m %v\n", disabledProviders)
	}
	if len(unknownProviders) > 0 {
		fmt.Printf("\033[33mUnknown IdP Providers (credential rejected before config check):\033[0m %v\n", unknownProviders)
	}

	if len(accessibleEndpoints) > 0 {
		fmt.Println("\n\033[32m[+] ACCESSIBLE PROJECT/TENANT ENDPOINTS:\033[0m")
		for _, ep := range accessibleEndpoints {
			fmt.Printf("    - %s\n", ep)
		}
	}

	if len(idTokenEndpoints) > 0 {
		fmt.Println("\n\033[34m[+] ENDPOINTS REQUIRING idToken:\033[0m")
		for _, ep := range idTokenEndpoints {
			fmt.Printf("    - %s\n", ep)
		}
	}

	if len(criticalFindings) > 0 {
		fmt.Println("\n\033[31m[!] CRITICAL FINDINGS:\033[0m")
		for _, f := range criticalFindings {
			fmt.Printf("    - %s\n", f)
		}
	}

	if len(enumFindings) > 0 {
		fmt.Println("\n\033[35m[!] EMAIL ENUMERATION VECTORS:\033[0m")
		seen := make(map[string]bool)
		for _, f := range enumFindings {
			if !seen[f] {
				fmt.Printf("    - %s\n", f)
				seen[f] = true
			}
		}
	}

	// Print security config from responses
	fmt.Println("\n[*] Discovered Configuration:")
	for _, r := range results {
		if r.Endpoint == "/v1/projects" && r.Success {
			if respMap, ok := r.Response.(map[string]interface{}); ok {
				if domains, ok := respMap["authorizedDomains"]; ok {
					fmt.Printf("    Authorized Domains: %v\n", domains)
				}
				if projectId, ok := respMap["projectId"]; ok {
					fmt.Printf("    Project ID: %v\n", projectId)
				}
			}
		}
		if r.Endpoint == "/v2/passwordPolicy" && r.Success {
			if respMap, ok := r.Response.(map[string]interface{}); ok {
				fmt.Printf("    Password Policy: %v\n", respMap)
			}
		}
	}
}

func extractProvider(endpoint string) string {
	start := strings.Index(endpoint, "(")
	end := strings.Index(endpoint, ")")
	if start != -1 && end != -1 {
		return endpoint[start+1 : end]
	}
	return "unknown"
}

func main() {
	apiKey := flag.String("key", "", "API key (required)")
	idToken := flag.String("idtoken", "", "ID token for authenticated endpoints")
	bearerToken := flag.String("bearer", "", "Bearer/access token for admin endpoints")
	email := flag.String("email", "", "Email address to test (for enumeration/auth testing)")
	password := flag.String("password", "", "Password to test with email")
	customToken := flag.String("customtoken", "", "Custom token (from Firebase Admin SDK)")
	phone := flag.String("phone", "", "Phone number to test (E.164 format: +15551234567)")
	projectID := flag.String("project", "", "Project ID (auto-discovered if not provided)")
	tenantIDs := flag.String("tenants", "", "Comma-separated tenant IDs (auto-discovered if not provided)")
	verbose := flag.Bool("v", false, "Verbose output - show all responses")
	flag.Parse()

	if *apiKey == "" {
		fmt.Println("Identity Toolkit Enumerator by RasterSec")
		fmt.Println("================================")
		fmt.Println("\nUsage: identitytoolkit-enum -key=<API_KEY> [options]")
		fmt.Println("\nThis tool checks the capabilities and scope of Google Identity Toolkit API keys/tokens.")
		fmt.Println("Useful for security assessments and penetration testing of Firebase/Identity Platform apps.")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  # Basic scan with just API key")
		fmt.Println("  identitytoolkit-enum -key=AIzaSy...")
		fmt.Println("")
		fmt.Println("  # Test specific email for enumeration")
		fmt.Println("  identitytoolkit-enum -key=AIzaSy... -email=admin@target.com")
		fmt.Println("")
		fmt.Println("  # Test with credentials")
		fmt.Println("  identitytoolkit-enum -key=AIzaSy... -email=user@target.com -password=pass123")
		fmt.Println("")
		fmt.Println("  # Full scan with idToken")
		fmt.Println("  identitytoolkit-enum -key=AIzaSy... -idtoken=eyJhbG...")
		fmt.Println("")
		fmt.Println("  # Specify project and tenants manually")
		fmt.Println("  identitytoolkit-enum -key=AIzaSy... -project=my-project -tenants=tenant1,tenant2")
		os.Exit(1)
	}

	// Handle URL-style key input
	key := *apiKey
	if strings.Contains(key, "key=") {
		parts := strings.Split(key, "key=")
		if len(parts) > 1 {
			key = strings.Split(parts[1], "&")[0]
		}
	}

	var tenantList []string
	if *tenantIDs != "" {
		tenantList = strings.Split(*tenantIDs, ",")
	}

	config := &Config{
		APIKey:      key,
		IDToken:     *idToken,
		BearerToken: *bearerToken,
		Email:       *email,
		Password:    *password,
		CustomToken: *customToken,
		Phone:       *phone,
		ProjectID:   *projectID,
		TenantIDs:   tenantList,
		Verbose:     *verbose,
	}

	fmt.Println("\nIdentity Toolkit Enumerator - v1.0.0")
	fmt.Println("https://www.rastersec.com")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("API Key: %s...%s\n", key[:min(8, len(key))], key[max(0, len(key)-4):])
	if config.IDToken != "" {
		fmt.Println("ID Token: provided")
	}
	if config.BearerToken != "" {
		fmt.Println("Bearer Token: provided")
	}
	if config.Email != "" {
		fmt.Printf("Test Email: %s\n", config.Email)
	}
	if config.Password != "" {
		fmt.Println("Test Password: provided")
	}
	if config.Phone != "" {
		fmt.Printf("Test Phone: %s\n", config.Phone)
	}
	if config.CustomToken != "" {
		fmt.Println("Custom Token: provided")
	}
	if config.ProjectID != "" {
		fmt.Printf("Project ID: %s (provided)\n", config.ProjectID)
	}
	if len(config.TenantIDs) > 0 {
		fmt.Printf("Tenant IDs: %v (provided)\n", config.TenantIDs)
	}

	checker := NewChecker(config)
	results := checker.CheckAll()

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("DETAILED RESULTS")
	fmt.Println(strings.Repeat("=", 70))

	for _, result := range results {
		printResult(result, config.Verbose)
	}

	printSummary(results)
}
