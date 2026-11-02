package gddy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ScopesEndpoint is the live static JSON endpoint hosted on GitHub Pages
const ScopesEndpoint = "https://im7548631-design.github.io/my-godaddy-scopes/api/scope.json"

const clientID = "bc87f347-af82-4892-833f-818f54a0e79e"
const redirectURI = "http://127.0.0.1:46579/callback"
const tokenEndpoint = "https://api.godaddy.com/v1/oauth2/access_token"

type ScopesResponse struct {
	Scopes []string `json:"scopes"`
}

type TokenCache struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

func getCredentialPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "gddy")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func saveToken(token TokenCache) error {
	path, err := getCredentialPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadToken() (*TokenCache, error) {
	path, err := getCredentialPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var token TokenCache
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func clearToken() error {
	path, err := getCredentialPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// FetchRemoteScopes retrieves the latest OAuth scopes from the deployed GitHub Pages endpoint
func FetchRemoteScopes(ctx context.Context) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ScopesEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for scopes: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch remote scopes from %s: %w", ScopesEndpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code fetching scopes: %d", resp.StatusCode)
	}

	var payload ScopesResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to decode scopes JSON: %w", err)
	}

	return payload.Scopes, nil
}

// Validate requested scopes against the remote canonical list with strict exit error message
func validateRequestedScopes(requested []string, allowed []string) error {
	allowedMap := make(map[string]bool)
	for _, scope := range allowed {
		allowedMap[scope] = true
	}

	var unsupported []string
	seen := make(map[string]bool)
	for _, req := range requested {
		if !allowedMap[req] && !seen[req] {
			unsupported = append(unsupported, req)
			seen[req] = true
		}
	}

	if len(unsupported) > 0 {
		return fmt.Errorf("unsupported OAuth scope(s) requested: %s", strings.Join(unsupported, ", "))
	}
	return nil
}

// Generate PKCE code verifier and challenge (S256)
func generatePKCE() (string, string) {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	verifier := base64.RawURLEncoding.EncodeToString(bytes)

	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge
}

// NewAuthCommand creates the auth subcommand group with login, status, logout, scope
func NewAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate and manage GoDaddy credentials",
	}

	cmd.AddCommand(newLoginCommand())
	cmd.AddCommand(newStatusCommand())
	cmd.AddCommand(newLogoutCommand())
	cmd.AddCommand(newScopeCommand())

	return cmd
}

func newLoginCommand() *cobra.Command {
	var provider string
	var env string
	var additionalScopes []string
	var outputFormat string
	var verboseFields string
	var dryRun bool
	var credentialStore string
	var interactive bool
	var timeout time.Duration
	var debugPattern string
	var schemaDump bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and cache credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if schemaDump {
				fmt.Println(`{"schema": "auth.login", "options": ["provider", "env", "scope", "output", "verbose", "dry-run", "credential-store", "interactive"]}`)
				return nil
			}

			if dryRun {
				fmt.Println("[Dry Run] Would initiate GoDaddy PKCE OAuth login flow and token exchange.")
				return nil
			}

			// 1. Fetch canonical scopes from deployed GitHub Pages endpoint
			fmt.Println("Fetching requestable OAuth scopes from deployed endpoint...")
			allowedScopes, err := FetchRemoteScopes(ctx)
			if err != nil {
				return fmt.Errorf("failed to fetch remote scopes for validation: %w", err)
			}

			// 2. Validate any user-supplied additional scopes against the remote list
			if len(additionalScopes) > 0 {
				if err := validateRequestedScopes(additionalScopes, allowedScopes); err != nil {
					return err // Exits immediately with the validation error message
				}
			}

			scopes := allowedScopes
			scopes = append(scopes, additionalScopes...)

			// 3. Generate PKCE values
			codeVerifier, codeChallenge := generatePKCE()

			// 4. Set up local callback listener on port 46579
			codeChan := make(chan string, 1)
			errChan := make(chan error, 1)

			listener, err := net.Listen("tcp", "127.0.0.1:46579")
			if err != nil {
				return fmt.Errorf("failed to bind local callback port 46579: %w", err)
			}
			defer listener.Close()

			mux := http.NewServeMux()
			mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
				code := r.URL.Query().Get("code")
				if code == "" {
					errChan <- fmt.Errorf("authorization code missing from callback query")
					http.Error(w, "Authorization failed: missing code", http.StatusBadRequest)
					return
				}
				fmt.Fprintln(w, "Authentication successful! You can close this browser window and return to your terminal.")
				codeChan <- code
			})

			server := &http.Server{Handler: mux}
			go func() {
				if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
					errChan <- err
				}
			}()
			defer server.Shutdown(context.Background())

			// 5. Construct Authorization URL
			query := url.Values{}
			query.Set("response_type", "code")
			query.Set("client_id", clientID)
			query.Set("redirect_uri", redirectURI)
			query.Set("scope", strings.Join(scopes, " "))
			query.Set("state", "63-BKw_FRSP2RRZMKLEwCQ")
			query.Set("nonce", "fQ__Y_BeV1aO_1l1dZvEZw")
			query.Set("code_challenge", codeChallenge)
			query.Set("code_challenge_method", "S256")

			authURL := fmt.Sprintf("https://api.godaddy.com/v2/oauth2/authorize?%s", query.Encode())

			fmt.Println("Opening browser for authentication…")
			fmt.Printf("If the browser does not open, visit:\n  %s\n", authURL)
			fmt.Println("Waiting for poll to complete to token generate pkce oauth to token exchange...")

			// 6. Wait for auth code or timeout
			var authCode string
			select {
			case authCode = <-codeChan:
				fmt.Println("Authorization code received. Exchanging code for tokens...")
			case callbackErr := <-errChan:
				return callbackErr
			case <-time.After(3 * time.Minute):
				return fmt.Errorf("authentication timed out waiting for browser callback")
			}

			// 7. Perform PKCE Token Exchange Request
			tokenData := url.Values{}
			tokenData.Set("grant_type", "authorization_code")
			tokenData.Set("client_id", clientID)
			tokenData.Set("code", authCode)
			tokenData.Set("redirect_uri", redirectURI)
			tokenData.Set("code_verifier", codeVerifier)

			resp, err := http.PostForm(tokenEndpoint, tokenData)
			if err != nil {
				return fmt.Errorf("token exchange request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("token exchange returned non-200 status code: %d", resp.StatusCode)
			}

			var tokenResult struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				TokenType    string `json:"token_type"`
				ExpiresIn    int    `json:"expires_in"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&tokenResult); err != nil {
				return fmt.Errorf("failed to parse token exchange response: %w", err)
			}

			cache := TokenCache{
				AccessToken:  tokenResult.AccessToken,
				RefreshToken: tokenResult.RefreshToken,
				TokenType:    tokenResult.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(tokenResult.ExpiresIn) * time.Second),
			}

			if err := saveToken(cache); err != nil {
				return fmt.Errorf("failed to save token to credential store: %w", err)
			}

			fmt.Println("Success! OAuth token exchange completed and credentials cached.")
			_ = provider
			_ = env
			_ = outputFormat
			_ = verboseFields
			_ = credentialStore
			_ = interactive
			_ = timeout
			_ = debugPattern

			return nil
		},
	}

	cmd.Flags().StringVar(&provider, "provider", "godaddy", "Auth provider name (one of: [godaddy])")
	cmd.Flags().StringVar(&env, "env", "", "Environment")
	cmd.StringArrayVarP(&additionalScopes, "scope", "s", nil, "Additional OAuth scope to request (repeatable)")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "human", "Output format: toon|json|human")
	cmd.Flags().StringVar(&verboseFields, "verbose", "", "Include metadata in output")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview mutations without executing")
	cmd.Flags().StringVar(&credentialStore, "credential-store", "auto", "Credential storage mode")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", true, "Force interactive prompts for missing inputs")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "Overall command timeout")
	cmd.Flags().StringVar(&debugPattern, "debug", "", "Enable debug logging")
	cmd.Flags().BoolVar(&schemaDump, "schema", false, "Dump output field metadata")

	return cmd
}

func newStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show cached credential status",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := loadToken()
			if err != nil {
				return fmt.Errorf("failed to read credential cache: %w", err)
			}
			if token == nil || token.AccessToken == "" {
				fmt.Println("Status: Not authenticated (no cached credentials found).")
				return nil
			}

			fmt.Println("Status: Authenticated")
			if !token.ExpiresAt.IsZero() {
				if time.Now().Before(token.ExpiresAt) {
					fmt.Printf("Token Valid Until: %s (Expires in %v)\n", token.ExpiresAt.Format(time.RFC1123), time.Until(token.ExpiresAt).Round(time.Second))
				} else {
					fmt.Println("Token State: Expired")
				}
			}
			return nil
		},
	}
}

func newLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear cached credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := clearToken(); err != nil {
				return fmt.Errorf("failed to clear credentials: %w", err)
			}
			fmt.Println("Successfully logged out. Cached GoDaddy credentials cleared.")
			return nil
		},
	}
}

func newScopeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "scope",
		Short: "List requestable OAuth scopes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fmt.Println("Fetching requestable OAuth scopes from GitHub Pages...")
			scopes, err := FetchRemoteScopes(ctx)
			if err != nil {
				return fmt.Errorf("failed to fetch scopes: %w", err)
			}
			fmt.Println("\nRequestable GoDaddy OAuth Scopes:")
			for _, s := range scopes {
				fmt.Printf("  - %s\n", s)
			}
			return nil
		},
	}
}
