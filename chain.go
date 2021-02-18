package goiptables

import (
	"bytes"
)

type Chain struct {
	Name    string
	Table   Table
	Options []Option
	Target  string
}

type Option string

// User-specifiable options
const (
	NumericOutput Option = "-n"
	Zero          Option = "-Z"
)

const (
	appendCommand      command = "-A"
	checkCommand       command = "-C"
	deleteCommand      command = "-D"
	insertCommand      command = "-I"
	replaceCommand     command = "-R"
	listCommand        command = "-L"
	listRulesCommand   command = "-S"
	flushCommand       command = "-F"
	zeroCommand        command = "-Z"
	newChainCommand    command = "-N"
	deleteChainCommand command = "-X"
	policyCommand      command = "-P"
	renameChainCommand command = "-E"
)

// Append appends a Rule to a Chain
func (c *Chain) Append(rule Rule) error {
	args, err := rule.Marshal()
	if err != nil {
		return err
	}
	_, err = runCommand(appendCommand, c.Name, args...)
	return err
}

// Checks if rule exists in Chain
func (c *Chain) Check(rule Rule) error {
	args, err := rule.Marshal()
	if err != nil {
		return err
	}
	_, err = runCommand(checkCommand, c.Name, args...)
	return err
}

// Delete removes a Rule from the specified Chain by its RuleSpecification
func (c *Chain) Delete(rule Rule) error {
	args, err := rule.Marshal()
	if err != nil {
		return err
	}
	_, err = runCommand(deleteCommand, c.Name, args...)
	return err
}

// DeleteByRuleNum removes a Rule from the specified Chain by RuleNumber
func (c *Chain) DeleteByRuleNum(rule Rule) error {
	_, err := runCommand(deleteCommand, c.Name, rule.RuleNumber)
	return err
}

// Insert inserts one rule as the rule number given by rule.RuleNumber.
// 1 is the default ruleNumber if none is specified
func (c *Chain) Insert(rule Rule) error {
	if rule.RuleNumber == "" {
		rule.RuleNumber = "1"
	}
	args, err := rule.Marshal()
	if err != nil {
		return err
	}

	_, err = runCommand(insertCommand, c.Name, args...)
	return err
}

// Replace replaces a Rule in the Chain
func (c *Chain) Replace(rule Rule) error {
	args, err := rule.Marshal()
	if err != nil {
		return err
	}
	_, err = runCommand(replaceCommand, c.Name, args...)
	return err
}

// List lists all Rules in the Chain and output a string
// If no Chain.Name is specified, Rules in all Chains will be listed
func (c *Chain) List() (string, error) {
	out, err := runCommand(listCommand, c.Name, "-v")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ListRules lists all Rules in the Chain
// If no Chain.Name is specified, Rules in all Chains will be listed
func (c *Chain) ListRules() ([]Rule, error) {
	args := []string{"-v"}
	if c.Table != "" {
		args = append(args, "-t", string(c.Table))
	}

	out, err := runCommand(listRulesCommand, c.Name, args...)
	if err != nil {
		return nil, err
	}
	// return parseListRules(c.Table, out)
	var rules []Rule
	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		rule, err := Unmarshal(line)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// Flush removes all Rules in the Chain
// If no Chain.Name is specified, all Chains will be Flushed
func (c *Chain) Flush() error {
	_, err := runCommand(flushCommand, c.Name)
	return err
}

// Zero the packet and byte counters in all chains
func (c *Chain) Zero(rule Rule) error {
	_, err := runCommand(zeroCommand, c.Name, rule.RuleNumber)
	return err
}

// NewChain creats a new user-defined chain of given Chain.Name
func (c *Chain) NewChain() error {
	_, err := runCommand(newChainCommand, c.Name)
	return err
}

// DeleteChain deletes the optional user-specified Chain.
// The Chain must be empty
// If no Chain.Name is pecified, every user-defined Chain will be deleted
func (c *Chain) DeleteChain() error {
	_, err := runCommand(deleteChainCommand, c.Name)
	return err
}

// Policy sets the policy for the given Chain to the Policy.Target.
// Only built-in chains can have POlicies
func (c *Chain) Policy(policy Policy) error {
	_, err := runCommand(policyCommand, c.Name, policy.Target)
	return err
}

// RenameChain renames the Chain to the specified name
func (c *Chain) RenameChain(name string) error {
	_, err := runCommand(renameChainCommand, c.Name, name)
	return err
}
