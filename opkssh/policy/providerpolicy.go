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

func (p ProvidersPolicyRow) ToString() string {
	return p.Issuer + " " + p.ClientID + " " + p.ExpirationPolicy
}

type ProviderPolicy struct {
	rows []ProvidersPolicyRow
}

func (p *ProviderPolicy) AddRow(row ProvidersPolicyRow) {
	p.rows = append(p.rows, row)
}

func (p *ProviderPolicy) CreateVerifier() (*verifier.Verifier, error) {
	pvs := []verifier.ProviderVerifier{}
	var expirationPolicy verifier.ExpirationPolicy
	var err error
	for _, row := range p.rows {
		var provider verifier.ProviderVerifier
		// TODO: We should handle this issuer matching in a more generic way
		// oidc.local and localhost: are a test issuers
		if row.Issuer == "https://accounts.google.com" ||
			strings.HasPrefix(row.Issuer, "http://oidc.local") ||
			strings.HasPrefix(row.Issuer, "http://localhost:") {

			opts := providers.GetDefaultGoogleOpOptions()
			opts.Issuer = row.Issuer
			opts.ClientID = row.ClientID
			provider = providers.NewGoogleOpWithOptions(opts)
		} else if strings.HasPrefix(row.Issuer, "https://login.microsoftonline.com") {
			opts := providers.GetDefaultAzureOpOptions()
			opts.Issuer = row.Issuer
			opts.ClientID = row.ClientID
			provider := providers.NewAzureOpWithOptions(opts)
			pvs = append(pvs, provider)
		} else {
			return nil, fmt.Errorf("unsupported issuer: %s", row.Issuer)
		}

		expirationPolicy, err = row.GetExpirationPolicy()
		if err != nil {
			return nil, err
		}
		pv := verifier.ProviderVerifierExpires{
			ProviderVerifier: provider,
			Expiration:       expirationPolicy,
		}
		pvs = append(pvs, pv)
	}

	if len(pvs) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}
	pktVerifier, err := verifier.NewFromMany(
		pvs,
		verifier.WithExpirationPolicy(expirationPolicy),
	)
	if err != nil {
		return nil, err
	}
	return pktVerifier, nil
}

func (p ProviderPolicy) ToString() string {
	var sb strings.Builder
	for _, row := range p.rows {
		sb.WriteString(row.ToString() + "\n")
	}
	return sb.String()
}

type ProvidersFileLoader struct {
	FileLoader
	Path string
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
	policy := o.FromTable(content, path)
	return policy, nil
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
// Path is passed only for logging purposes
func (o *ProvidersFileLoader) FromTable(input []byte, path string) *ProviderPolicy {
	configLog := config.ConfigLogSingleton()
	table := config.NewTable(input)
	policy := &ProviderPolicy{
		rows: []ProvidersPolicyRow{},
	}
	for i, row := range table.GetRows() {
		// Error should not break everyone's ability to login, skip those rows
		if len(row) != 3 {
			configProblem := config.Entry{
				Filepath:            path,
				OffendingLine:       strings.Join(row, " "),
				OffendingLineNumber: i,
				ErrorMessage:        fmt.Sprintf("wrong number of arguments (expected=3, got=%d)", len(row)),
				Source:              "providers policy file",
			}
			configLog.WriteEntry(configProblem)
			continue
		}
		policyRow := ProvidersPolicyRow{
			Issuer:           row[0],
			ClientID:         row[1],
			ExpirationPolicy: row[2], //TODO: Validate this so that we can determine the line number that has the error
		}
		policy.AddRow(policyRow)
	}
	return policy
}
