package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// CachedQuote represents the persisted state of a locked registration quote
type CachedQuote struct {
	Domain          string                 `json:"domain"`
	Period          uint64                 `json:"period"`
	AgreementTypes  []string               `json:"agreementTypes"`
	AgreementTitles []string               `json:"agreementTitles"`
	Price           string                 `json:"price,omitempty"`
	Currency        string                 `json:"currency,omitempty"`
	ExpiresAt       string                 `json:"expiresAt,omitempty"`
	Profile         map[string]interface{} `json:"profile,omitempty"`
	IdempotencyKey  string                 `json:"idempotencyKey,omitempty"`
	Fees            interface{}            `json:"fees,omitempty"`
}

func getQuoteCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "gddy", "quotes")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func SaveQuoteCache(token string, quote CachedQuote) error {
	dir, err := getQuoteCacheDir()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(quote, "", "  ")
	if err != nil {
		return err
	}
	filePath := filepath.Join(dir, token+".json")
	return os.WriteFile(filePath, data, 0600)
}

// NewDomainQuoteCommand creates the live quote subcommand for domain registrations using GoDaddy v3 API
func NewDomainQuoteCommand() *cobra.Command {
	var period uint64
	var privacy bool
	var noRenew bool
	var nameservers []string
	var schemaDump bool

	cmd := &cobra.Command{
		Use:   "quote <domain>",
		Short: "Price a domain registration and lock a quote",
		Long: `Quote a single-domain registration: returns the registration price, 
the legal agreements you must accept, the contact/preference settings that would apply, 
and a single-use quote token (valid ~10 minutes). Quoting is free and changes nothing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			targetDomain := args[0]

			if schemaDump {
				fmt.Println(`{"schema": "domain.quote", "options": ["period", "privacy", "no-renew", "nameserver"]}`)
				return nil
			}

			renewAuto := !noRenew
			apiURL := "https://api.godaddy.com/v3/domains/registration-quotes"

			payload := map[string]interface{}{
				"domain": targetDomain,
				"period": period,
				"profile": map[string]interface{}{
					"privacy":   privacy,
					"autoRenew": renewAuto,
				},
			}
			if len(nameservers) > 0 {
				payload["profile"].(map[string]interface{})["nameServers"] = nameservers
			}

			bodyBytes, err := json.Marshal(payload)
			if err != nil {
				return fmt.Errorf("failed to marshal registration quote payload: %w", err)
			}

			httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(bodyBytes))
			if err != nil {
				return fmt.Errorf("failed to create registration quote request: %w", err)
			}
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("Accept", "application/json")
			// Note: Bearer authorization token is injected automatically by client middleware.

			client := &http.Client{Timeout: 20 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				return fmt.Errorf("registration quote request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("GoDaddy v3 API returned error status code %d while quoting domain registration", resp.StatusCode)
			}

			var quoteResp struct {
				Domain             string   `json:"domain"`
				Available          bool     `json:"available"`
				QuoteToken         string   `json:"quoteToken"`
				ExpiresAt          string   `json:"expiresAt"`
				Price              *struct {
					Amount       string `json:"amount"`
					CurrencyCode string `json:"currencyCode"`
				} `json:"price,omitempty"`
				RenewalPrice *struct {
					Amount       string `json:"amount"`
					CurrencyCode string `json:"currencyCode"`
				} `json:"renewalPrice,omitempty"`
				RequiredAgreements []struct {
					AgreementType string `json:"agreementType"`
					Title         string `json:"title"`
					URL           string `json:"url"`
				} `json:"requiredAgreements,omitempty"`
				Fees interface{} `json:"fees,omitempty"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&quoteResp); err != nil {
				return fmt.Errorf("failed to decode quote API response: %w", err)
			}

			// Build human/scripting output
			var agreementLines []string
			var agreementTypes []string
			var agreementTitles []string
			for _, ag := range quoteResp.RequiredAgreements {
				line := ag.Title
				if ag.URL != "" {
					line = fmt.Sprintf("%s (%s)", ag.Title, ag.URL)
				}
				agreementLines = append(agreementLines, line)
				agreementTypes = append(agreementTypes, ag.AgreementType)
				agreementTitles = append(agreementTitles, ag.Title)
			}

			result := map[string]interface{}{
				"domain":      quoteResp.Domain,
				"available":   quoteResp.Available,
				"period":      period,
				"periodLabel": fmt.Sprintf("%d year", period),
				"quoteToken":  quoteResp.QuoteToken,
				"expiresAt":   quoteResp.ExpiresAt,
				"agreements":  strings.Join(agreementLines, "; "),
			}

			var priceStr, currencyStr string
			if quoteResp.Price != nil {
				result["price"] = quoteResp.Price.Amount
				result["currency"] = quoteResp.Price.CurrencyCode
				priceStr = quoteResp.Price.Amount
				currencyStr = quoteResp.Price.CurrencyCode
			}
			if quoteResp.RenewalPrice != nil {
				result["renewalPrice"] = quoteResp.RenewalPrice.Amount
			}
			if len(quoteResp.RequiredAgreements) > 0 {
				result["requiredAgreements"] = quoteResp.RequiredAgreements
			}
			if quoteResp.Fees != nil {
				result["fees"] = quoteResp.Fees
			}

			// Persist quote token to local cache for subsequent purchase validation
			if quoteResp.Available && quoteResp.QuoteToken != "" {
				cached := CachedQuote{
					Domain:          quoteResp.Domain,
					Period:          period,
					AgreementTypes:  agreementTypes,
					AgreementTitles: agreementTitles,
					Price:           priceStr,
					Currency:        currencyStr,
					ExpiresAt:       quoteResp.ExpiresAt,
					Fees:            quoteResp.Fees,
				}
				if cacheErr := SaveQuoteCache(quoteResp.QuoteToken, cached); cacheErr != nil {
					return fmt.Errorf("failed to persist locked quote locally: %w", cacheErr)
				}
			}

			prettyJSON, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(prettyJSON))

			if quoteResp.Available && quoteResp.QuoteToken != "" {
				fmt.Printf("\nNext Action:\n  gddy domain purchase --quote-token %s\n", quoteResp.QuoteToken)
			}

			return nil
		},
	}

	cmd.Flags().Uint64Var(&period, "period", 1, "Registration length in years (1-10)")
	cmd.Flags().BoolVar(&privacy, "privacy", false, "Add privacy protection to the registration")
	cmd.Flags().BoolVar(&noRenew, "no-renew", false, "Disable auto-renewal (auto-renew is on by default)")
	cmd.Flags().StringSliceVar(&nameservers, "nameserver", nil, "Custom nameserver (repeatable)")
	cmd.Flags().BoolVar(&schemaDump, "schema", false, "Dump output field metadata instead of running the command")

	return cmd
}
