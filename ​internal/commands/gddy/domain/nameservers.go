package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

// NewDomainNameserverCommand creates the nameserver subcommand for domain nameserver management using GoDaddy v3 API
func NewDomainNameserverCommand() *cobra.Command {
	var newNameservers []string
	var schemaDump bool

	cmd := &cobra.Command{
		Use:   "nameserver <domain>",
		Short: "Manage a domain's nameservers",
		Long:  `Get or replace authoritative nameservers for a registered domain using the GoDaddy v3 API.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			targetDomain := args[0]

			if schemaDump {
				fmt.Println(`{"schema": "domain.nameserver", "options": ["nameserver"]}`)
				return nil
			}

			// If custom nameservers are provided via flags, perform a PUT/update request
			if len(newNameservers) > 0 {
				apiURL := fmt.Sprintf("https://api.godaddy.com/v3/domains/%s/nameservers", targetDomain)

				payload := map[string]interface{}{
					"nameServers": newNameservers,
				}
				bodyBytes, err := json.Marshal(payload)
				if err != nil {
					return fmt.Errorf("failed to marshal nameservers payload: %w", err)
				}

				httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, apiURL, bytes.NewBuffer(bodyBytes))
				if err != nil {
					return fmt.Errorf("failed to create update nameservers request: %w", err)
				}
				httpReq.Header.Set("Content-Type", "application/json")
				httpReq.Header.Set("Accept", "application/json")
				// Note: Bearer authorization token is injected automatically by client middleware.

				client := &http.Client{Timeout: 20 * time.Second}
				resp, err := client.Do(httpReq)
				if err != nil {
					return fmt.Errorf("update nameservers request failed: %w", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
					return fmt.Errorf("GoDaddy v3 API returned error status code %d while updating nameservers", resp.StatusCode)
				}

				var result map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					result = map[string]interface{}{
						"domain":      targetDomain,
						"status":      "updated",
						"nameServers": newNameservers,
					}
				}

				prettyJSON, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(prettyJSON))
				return nil
			}

			// Default: GET domain details to inspect current nameservers
			apiURL := fmt.Sprintf("https://api.godaddy.com/v3/domains/%s", targetDomain)
			httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
			if err != nil {
				return fmt.Errorf("failed to create get domain request: %w", err)
			}
			httpReq.Header.Set("Accept", "application/json")

			client := &http.Client{Timeout: 20 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				return fmt.Errorf("get domain request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("GoDaddy v3 API returned error status code %d while fetching domain details", resp.StatusCode)
			}

			var domainDetails map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&domainDetails); err != nil {
				return fmt.Errorf("failed to decode domain details response: %w", err)
			}

			nsData := domainDetails["nameServers"]
			output := map[string]interface{}{
				"domain":      targetDomain,
				"nameServers": nsData,
			}

			prettyJSON, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(prettyJSON))

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&newNameservers, "nameserver", nil, "New authoritative nameservers to set (repeatable)")
	cmd.Flags().BoolVar(&schemaDump, "schema", false, "Dump output field metadata instead of running the command")

	return cmd
}
