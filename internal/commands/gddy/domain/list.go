package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// NewDomainListCommand creates the list subcommand for domains using GoDaddy v3 API
func NewDomainListCommand() *cobra.Command {
	var pageSize int
	var pageToken string
	var statuses []string
	var lifecycleGroups []string
	var updatedAfter string
	var expiresBefore string
	var schemaDump bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the domains in your account",
		Long:  `Returns a paginated collection of domain names owned by the authenticated account via GoDaddy v3 API.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if schemaDump {
				fmt.Println(`{"schema": "domain.list", "options": ["page-size", "page-token", "status", "lifecycle-group", "updated-after", "expires-before"]}`)
				return nil
			}

			apiURL, err := url.Parse("https://api.godaddy.com/v3/domains/domain-names")
			if err != nil {
				return fmt.Errorf("failed to parse API base URL: %w", err)
			}

			query := apiURL.Query()
			if pageSize > 0 {
				query.Set("pageSize", fmt.Sprintf("%d", pageSize))
			}
			if pageToken != "" {
				query.Set("pageToken", pageToken)
			}
			if len(statuses) > 0 {
				query.Set("statuses", strings.Join(statuses, ","))
			}
			if len(lifecycleGroups) > 0 {
				query.Set("lifecycleGroups", strings.Join(lifecycleGroups, ","))
			}
			if updatedAfter != "" {
				query.Set("updatedAfter", updatedAfter)
			}
			if expiresBefore != "" {
				query.Set("expiresBefore", expiresBefore)
			}
			apiURL.RawQuery = query.Encode()

			httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
			if err != nil {
				return fmt.Errorf("failed to create list domains request: %w", err)
			}
			httpReq.Header.Set("Accept", "application/json")
			// Note: Bearer authorization token is injected automatically by client middleware.

			client := &http.Client{Timeout: 20 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				return fmt.Errorf("list domains request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("GoDaddy v3 API returned error status code %d while listing domains", resp.StatusCode)
			}

			var listResp struct {
				Domains []map[string]interface{} `json:"domains"`
				Links   []map[string]interface{} `json:"links,omitempty"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
				return fmt.Errorf("failed to decode list domains API response: %w", err)
			}

			prettyJSON, _ := json.MarshalIndent(listResp, "", "  ")
			fmt.Println(string(prettyJSON))

			return nil
		},
	}

	cmd.Flags().IntVar(&pageSize, "page-size", 100, "Maximum number of domains in the response (1-200)")
	cmd.Flags().StringVar(&pageToken, "page-token", "", "Opaque cursor from the previous page's next link")
	cmd.Flags().StringSliceVar(&statuses, "status", nil, "Filter results by lifecycle statuses (e.g. ACTIVE, EXPIRED)")
	cmd.Flags().StringSliceVar(&lifecycleGroups, "lifecycle-group", nil, "Filter results by status groups (e.g. REGISTERED, PENDING)")
	cmd.Flags().StringVar(&updatedAfter, "updated-after", "", "Return only domains last updated after this timestamp (RFC 3339)")
	cmd.Flags().StringVar(&expiresBefore, "expiresBefore", "", "Return only domains expiring before this timestamp (RFC 3339)")
	cmd.Flags().BoolVar(&schemaDump, "schema", false, "Dump output field metadata instead of running the command")

	return cmd
}
