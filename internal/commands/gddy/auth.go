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

type ScopeDetail struct {
	Scope       string   `json:"scope"`
	Description string   `json:"description"`
	Default     bool     `json:"default"`
	Commands    []string `json:"commands"`
}

type ScopesResponse struct {
	Scopes []ScopeDetail `json:"scopes"`
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

// FetchRemoteScopes retrieves the latest OAuth scope objects from the deployed GitHub Pages endpoint
func FetchRemoteScopes(ctx context.Context) ([]ScopeDetail, error) {
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

// Validate requested scope strings against the remote canonical list with strict exit error message
func validateRequestedScopes(requested []string, allowed []ScopeDetail) error {
	allowedMap := make(map[string]bool)
	for _, s := range allowed {
		allowedMap[s.Scope] = true
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

type commonAuthOptions struct {
	provider        string
	env             string
	outputFormat    string
	verboseFields   string
	fields          string
	filter          string
	expr            string
	schemaDump      bool
	timeout         time.Duration
	debugPattern    string
	credentialStore string
	interactive     bool
	dryRun          bool
}

func addCommonFlags(cmd *cobra.Command, opts *commonAuthOptions, includeDryRun bool) {
	cmd.Flags().StringVar(&opts.provider, "provider", "godaddy", "Auth provider name (one of: [godaddy])")
	cmd.Flags().StringVar(&opts.env, "env", "", "Override the active environment (see: env list)")
	cmd.Flags().StringVarP(&opts.outputFormat, "output", "o", "human", "Output format: toon|json|human")
	cmd.Flags().StringVar(&opts.verboseFields, "verbose", "", "Include metadata in output")
	if includeDryRun {
		cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "Preview mutations without executing")
	}
	cmd.Flags().StringVar(&opts.fields, "fields", "scope,description,commands,default", "Comma-separated fields to include in output")
	cmd.Flags().StringVar(&opts.filter, "filter", "", "Per-item JMESPath predicate for list data")
	cmd.Flags().StringVar(&opts.expr, "expr", "", "JMESPath query applied to the whole result")
	cmd.Flags().BoolVar(&opts.schemaDump, "schema", false, "Dump output field metadata instead of running the command")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 0, "Overall command timeout (e.g. 60s, 5m)")
	cmd.Flags().StringVar(&opts.debugPattern, "debug", "", "Enable debug logging")
	cmd.Flags().StringVar(&opts.credentialStore, "credential-store", "auto", "Credential storage mode")
	cmd.Flags().BoolVarP(&opts.interactive, "interactive", "i", true, "Force interactive prompts for missing inputs")
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
	var additionalScopes []string
	var opts commonAuthOptions

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and cache credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if opts.schemaDump {
				fmt.Println(`{"schema": "auth.login", "options": ["provider", "env", "scope", "output", "verbose", "dry-run", "credential-store", "interactive"]}`)
				return nil
			}

			if opts.dryRun {
				fmt.Println("[Dry Run] Would initiate GoDaddy PKCE OAuth login flow and token exchange.")
				return nil
			}

			fmt.Println("Fetching requestable OAuth scopes from deployed endpoint...")
			allowedScopes, err := FetchRemoteScopes(ctx)
			if err != nil {
				return fmt.Errorf("failed to fetch remote scopes for validation: %w", err)
			}

			if len(additionalScopes) > 0 {
				if err := validateRequestedScopes(additionalScopes, allowedScopes); err != nil {
					return err
				}
			}

			var scopeStrs []string
			for _, s := range allowedScopes {
				scopeStrs = append(scopeStrs, s.Scope)
			}
			scopeStrs = append(scopeStrs, additionalScopes...)

			codeVerifier, codeChallenge := generatePKCE()

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

			query := url.Values{}
			query.Set("response_type", "code")
			query.Set("client_id", clientID)
			query.Set("redirect_uri", redirectURI)
			query.Set("scope", strings.Join(scopeStrs, " "))
			query.Set("state", "63-BKw_FRSP2RRZMKLEwCQ")
			query.Set("nonce", "fQ__Y_BeV1aO_1l1dZvEZw")
			query.Set("code_challenge", codeChallenge)
			query.Set("code_challenge_method", "S256")

			authURL := fmt.Sprintf("https://api.godaddy.com/v2/oauth2/authorize?%s", query.Encode())

			fmt.Println("Opening browser for authentication…")
			fmt.Printf("If the browser does not open, visit:\n  %s\n", authURL)

			var authCode string
			select {
			case authCode = <-codeChan:
				fmt.Println("Authorization code received. Exchanging code for tokens...")
			case callbackErr := <-errChan:
				return callbackErr
			case <-time.After(3 * time.Minute):
				return fmt.Errorf("authentication timed out waiting for browser callback")
			}

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
			return nil
		},
	}

	addCommonFlags(cmd, &opts, true)
	cmd.Flags().StringArrayVarP(&additionalScopes, "scope", "s", nil, "Additional OAuth scope to request (repeatable, one per flag)")

	return cmd
}

func newStatusCommand() *cobra.Command {
	var opts commonAuthOptions

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show cached credential status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.schemaDump {
				fmt.Println(`{"schema": "auth.status", "options": ["provider", "env", "output", "verbose", "credential-store"]}`)
				return nil
			}

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

	addCommonFlags(cmd, &opts, false)
	return cmd
}

func newLogoutCommand() *cobra.Command {
	var opts commonAuthOptions

	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Clear cached credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.schemaDump {
				fmt.Println(`{"schema": "auth.logout", "options": ["provider", "env", "output", "verbose", "dry-run", "credential-store"]}`)
				return nil
			}

			if opts.dryRun {
				fmt.Println("[Dry Run] Would clear cached GoDaddy credentials.")
				return nil
			}

			if err := clearToken(); err != nil {
				return fmt.Errorf("failed to clear credentials: %w", err)
			}
			fmt.Println("Successfully logged out. Cached GoDaddy credentials cleared.")
			return nil
		},
	}

	addCommonFlags(cmd, &opts, true)
	return cmd
}

func newScopeCommand() *cobra.Command {
	var commandFilter string
	var defaultsOnly bool
	var nonDefault bool
	var opts commonAuthOptions

	cmd := &cobra.Command{
		Use:   "scope",
		Short: "List requestable OAuth scopes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if opts.schemaDump {
				fmt.Println(`{"schema": "auth.scope", "options": ["command", "defaults-only", "non-default", "output", "verbose", "fields", "filter", "expr"]}`)
				return nil
			}

			scopes, err := FetchRemoteScopes(ctx)
			if err != nil {
				return fmt.Errorf("failed to fetch scopes: %w", err)
			}

			var filtered []ScopeDetail
			for _, s := range scopes {
				if defaultsOnly && !s.Default {
					continue
				}
				if nonDefault && s.Default {
					continue
				}
				if commandFilter != "" {
					matched := false
					for _, cmdName := range s.Commands {
						if strings.EqualFold(cmdName, commandFilter) {
							matched = true
							break
						}
					}
					if !matched {
						continue
					}
				}
				filtered = append(filtered, s)
			}

			if opts.outputFormat == "json" {
				data, _ := json.MarshalIndent(filtered, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Println("Requestable GoDaddy OAuth Scopes:")
			for _, s := range filtered {
				defTag := ""
				if s.Default {
					defTag = " [default]"
				}
				fmt.Printf("  - %s%s\n    Description: %s\n    Commands:    %s\n\n", s.Scope, defTag, s.Description, strings.Join(s.Commands, ", "))
			}
			return nil
		},
	}

	addCommonFlags(cmd, &opts, false)
	cmd.Flags().StringVar(&commandFilter, "command", "", `Only show scopes required by this command (e.g. "domain purchase")`)
	cmd.Flags().BoolVar(&defaultsOnly, "defaults-only", false, "Only show scopes requested at login by default")
	cmd.Flags().BoolVar(&nonDefault, "non-default", false, "Only show the sensitive scopes that prompt the first time a command needs them")

	return cmd
}
