package policy

import (
	"fmt"

	"github.com/openpubkey/openpubkey/opkssh/config"
)

type OpPolicy struct {
	Issuer           string
	ClientID         string
	ExpirationPolicy string
}

// FromTable decodes whitespace delimited input into policy.Policy
func (o OpPolicy) ToTable(opPolicies []OpPolicy) config.Table {
	table := config.Table{}
	for _, opPolicy := range opPolicies {
		table.AddRow(opPolicy.Issuer, opPolicy.ClientID, opPolicy.ExpirationPolicy)
	}
	return table
}

// FromTable decodes whitespace delimited input into policy.Policy
func (o OpPolicy) FromTable(input []byte) ([]OpPolicy, error) {
	table := config.NewTable(input)
	policies := []OpPolicy{}
	errors := []error{}
	for _, row := range table.GetRows() {
		// Error should not break everyone's ability to login, skip those rows
		if len(row) != 3 {
			errors = append(errors, fmt.Errorf("invalid row: %v", row))
			continue
		}
		opPolicy := OpPolicy{
			Issuer:           row[0],
			ClientID:         row[1],
			ExpirationPolicy: row[2], //TODO: Validate this here
		}
		policies = append(policies, opPolicy)
	}

	// TODO: We should log non-critical errors rather than failing.
	if len(errors) > 0 {
		return nil, errors[0]
	}
	return policies, nil
}
