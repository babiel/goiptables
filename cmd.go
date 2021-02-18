package goiptables

import (
	"bytes"
	"fmt"
	"os/exec"
)

type command string

// runCommand is the primary command func; sends stdout & stderr to the function's []byte and err return values
func runCommand(command command, obj string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(iptablesCommand)
	if err != nil {
		return nil, err
	}
	cmdArgs := append([]string{path, string(command), obj}, args...)

	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd := exec.Cmd{
		Path:   path,
		Args:   cmdArgs,
		Stdout: &stdout,
		Stderr: &stderr,
	}

	// run cmd
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, stderr.String())
	}

	if stderr.Len() != 0 {
		return nil, fmt.Errorf("%s", stderr.String())
	}

	return stdout.Bytes(), nil
}
