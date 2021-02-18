package goiptables

import (
	"strings"
)

type Table string

const (
	Filter Table = "filter"
	Nat    Table = "nat"
	Mangle Table = "mangle"
	Raw    Table = "raw"
)

const (
	listChainsCommand command = "-t"
)

// tableIsValid returns true if a Table is permitted by iptables
func tableIsValid(name Table) bool {
	validTables := []Table{Filter, Nat, Mangle, Raw}
	for _, t := range validTables {
		if t == name {
			return true
		}
	}
	return false
}

// ListChains returns a slice containing the name of each chain in the specified table.
func (t Table) ListChains() ([]Chain, error) {
	out, err := runCommand(listChainsCommand, string(t), "-S")
	if err != nil {
		return nil, err
	}

	rules := strings.Split(string(out), "\n")

	// strip trailing newline
	if len(rules) > 0 && rules[len(rules)-1] == "" {
		rules = rules[:len(rules)-1]
	}

	// Iterate over rules to find all default (-P) and user-specified (-N) chains.
	// Chains definition always come before rules.
	// Format is the following:
	// -P OUTPUT ACCEPT
	// -N Custom
	var chains []Chain
	for _, val := range rules {
		if strings.HasPrefix(val, "-P") || strings.HasPrefix(val, "-N") {
			chains = append(chains, Chain{
				Name:  strings.Fields(val)[1],
				Table: t,
			})
		} else {
			break
		}
	}

	return chains, nil
}
