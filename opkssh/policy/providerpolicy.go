package policy

import (
	"fmt"
	"strings"

	"github.com/openpubkey/openpubkey/opkssh/config"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/spf13/afero"
)

type ProvidersPolicyRow struct {
	Issuer           string
	ClientID         string
	ExpirationPolicy string
}

func (p ProvidersPolicyRow) GetExpirationPolicy() (verifier.ExpirationPolicy, error) {
	switch p.ExpirationPolicy {
	case "24h":
		return verifier.ExpirationPolicies.MAX_AGE_24HOURS, nil
	case "48h":
		return verifier.ExpirationPolicies.MAX_AGE_48HOURS, nil
	case "1week":
		return verifier.ExpirationPolicies.MAX_AGE_1WEEK, nil
	case "oidc":
		return verifier.ExpirationPolicies.OIDC, nil
	case "oidc_refreshed":
		return verifier.ExpirationPolicies.OIDC_REFRESHED, nil
	case "never":
		return verifier.ExpirationPolicies.NEVER_EXPIRE, nil
	default:
		return verifier.ExpirationPolicy{}, fmt.Errorf("invalid expiration policy: %s", p.ExpirationPolicy)
	}

}

type ProviderPolicy struct {
	FileLoader
	rows []ProvidersPolicyRow
}

func (p *ProviderPolicy) AddRow(row ProvidersPolicyRow) {
	p.rows = append(p.rows, row)
}

func (p *ProviderPolicy) CreateVerifier() (*verifier.Verifier, error) {
	ops := []verifier.ProviderVerifier{}
	var expirationPolicy verifier.ExpirationPolicy
	var err error
	for _, row := range p.rows {
		// TODO: This just overwrites the expiration policy for all providers. We need to modify the verifier to support a expiration policies per provider
		expirationPolicy, err = row.GetExpirationPolicy()
		if err != nil {
			return nil, err
		}
		// TODO: We should handle this issuer matching in a more generic way
		if row.Issuer == "https://accounts.google.com" {
			opts := providers.GetDefaultGoogleOpOptions()
			opts.Issuer = row.Issuer
			opts.ClientID = row.ClientID
			provider := providers.NewGoogleOpWithOptions(opts)
			ops = append(ops, provider)
		} else if strings.HasPrefix(row.Issuer, "https://login.microsoftonline.com") {
			opts := providers.GetDefaultAzureOpOptions()
			opts.Issuer = row.Issuer
			opts.ClientID = row.ClientID
			provider := providers.NewAzureOpWithOptions(opts)
			ops = append(ops, provider)
		} else {
			return nil, fmt.Errorf("unsupported issuer: %s", row.Issuer)
		}
	}

	if len(ops) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}

	pktVerifier, err := verifier.New(
		ops[0],
		verifier.WithExpirationPolicy(expirationPolicy),
		verifier.AddProviderVerifiers(ops[1:]...),
	)
	if err != nil {
		return nil, err
	}
	return pktVerifier, nil
}

type ProvidersFileLoader struct {
	FileLoader
}

func NewProviderFileLoader() *ProvidersFileLoader {
	return &ProvidersFileLoader{
		FileLoader: FileLoader{
			Fs: afero.NewOsFs(),
		},
	}
}

func (o *ProvidersFileLoader) LoadProviderPolicy(path string) (*ProviderPolicy, error) {
	content, err := o.FileLoader.LoadFileAtPath(path)
	if err != nil {
		return nil, err
	}
	policy, err := o.FromTable(content)
	if err != nil {
		return nil, err
	}
	return policy, err
}

// FromTable decodes whitespace delimited input into policy.Policy
func (o ProvidersFileLoader) ToTable(opPolicies ProviderPolicy) config.Table {
	table := config.Table{}
	for _, opPolicy := range opPolicies.rows {
		table.AddRow(opPolicy.Issuer, opPolicy.ClientID, opPolicy.ExpirationPolicy)
	}
	return table
}

// FromTable decodes whitespace delimited input into policy.Policy
func (o *ProvidersFileLoader) FromTable(input []byte) (*ProviderPolicy, error) {
	table := config.NewTable(input)
	policy := &ProviderPolicy{
		rows: []ProvidersPolicyRow{},
	}
	errors := []error{}
	for _, row := range table.GetRows() {
		// Error should not break everyone's ability to login, skip those rows
		if len(row) != 3 {
			errors = append(errors, fmt.Errorf("invalid row: %v", row))
			continue
		}
		policyRow := ProvidersPolicyRow{
			Issuer:           row[0],
			ClientID:         row[1],
			ExpirationPolicy: row[2], //TODO: Validate this so that we can determine the line number that has the error
		}
		policy.AddRow(policyRow)
	}

	// TODO: We should log non-critical errors rather than failing.
	if len(errors) > 0 {
		return nil, errors[0]
	}
	return policy, nil
}
