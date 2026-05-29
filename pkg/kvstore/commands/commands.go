// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/kvstore"
)

// TestCommands returns the test script commands associated with the given client.
func TestCommands(client kvstore.Client) map[string]script.Cmd {
	cmds := cmds{client: client}
	return map[string]script.Cmd{
		"kvstore/update": cmds.update(),
		"kvstore/delete": cmds.delete(),
		"kvstore/list":   cmds.list(),
	}
}

// Commands returns the script commands associated with the given client.
func Commands(client kvstore.Client) map[string]script.Cmd {
	cmds := cmds{client: client}
	return map[string]script.Cmd{
		"kvstore/list": cmds.list(),
	}
}

type cmds struct{ client kvstore.Client }

func handleJSONInput(key string, value []byte) ([]byte, error) {
	switch getKeyType(key) {
	case keyTypeJSON:
		return value, nil
	case keyTypeBlob, keyTypeUnknown:
		return nil, fmt.Errorf("cannot handle JSON input for key %q", key)
	}

	prefixTranscodableInfo, err := lookupPrefixTranscodableJSONInfo(key)
	if err != nil {
		return nil, err
	}
	return transcodeFromJSON(prefixTranscodableInfo, value)
}

func (c cmds) update() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "update kvstore key-value",
			Args:    "key value-file",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("input", "i", "plain", "Input format. One of: (plain, json)")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected key and value file", script.ErrUsage)
			}
			key := args[0]
			value, err := os.ReadFile(s.Path(args[1]))
			if err != nil {
				return nil, fmt.Errorf("could not read %q: %w", s.Path(args[1]), err)
			}

			// As this is a dev/test only command, we can be a bit more
			// aggressive with trimming whitespace to simplify our test scripts.
			value = bytes.TrimSpace(value)

			infmt, _ := s.Flags.GetString("input")
			switch infmt {
			case "plain":
			case "json":
				value, err = handleJSONInput(key, value)
			default:
				return nil, fmt.Errorf("unexpected input format %q", infmt)
			}
			if err != nil {
				return nil, err
			}

			return nil, c.client.Update(s.Context(), args[0], value, false)
		},
	)
}

func (c cmds) delete() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "delete kvstore key-value",
			Args:    "key",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected key", script.ErrUsage)
			}
			return nil, c.client.Delete(s.Context(), args[0])
		},
	)
}

func handleJSONOutput(b *bytes.Buffer, key string, value []byte, auto bool) error {
	keyType := getKeyType(key)
	if keyType == keyTypeBlobTranscodableJSON {
		prefixTranscodableInfo, err := lookupPrefixTranscodableJSONInfo(key)
		if err != nil {
			return err
		}
		value, err = transcodeToJSON(prefixTranscodableInfo, key, value)
		if err != nil {
			return err
		}
		keyType = keyTypeJSON
	}

	switch keyType {
	case keyTypeJSON:
		if err := json.Indent(b, value, "", "  "); err != nil {
			return err
		}
		fmt.Fprintln(b)

	default:
		if !auto {
			return fmt.Errorf("cannot handle JSON output for key %q of type %q", key, getKeyType(key))
		}
		fmt.Fprintln(b, string(value))
	}

	return nil
}

func (c cmds) list() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "list kvstore key-value pairs",
			Args:    "prefix (output file)",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "auto", "Output format. One of: (auto, plain, json)")
				fs.Bool("keys-only", false, "Only output the listed keys")
				fs.Bool("values-only", false, "Only output the listed values")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var prefix string
			if len(args) > 0 {
				prefix = args[0]
			}

			keysOnly, _ := s.Flags.GetBool("keys-only")
			valuesOnly, _ := s.Flags.GetBool("values-only")
			if keysOnly && valuesOnly {
				return nil, errors.New("--keys-only and --values-only are mutually exclusive")
			}

			kvs, err := c.client.ListPrefix(s.Context(), prefix)
			if err != nil {
				return nil, fmt.Errorf("error listing %q: %w", prefix, err)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				var b bytes.Buffer
				for _, k := range slices.Sorted(maps.Keys(kvs)) {
					if !valuesOnly {
						fmt.Fprintf(&b, "# %s\n", k)
					}

					if !keysOnly {
						outfmt, _ := s.Flags.GetString("output")
						switch outfmt {
						case "plain":
							fmt.Fprintln(&b, string(kvs[k].Data))
						case "json", "auto":
							if err := handleJSONOutput(&b, k, kvs[k].Data, outfmt == "auto"); err != nil {
								fmt.Fprintf(&b, "ERROR: %s\n", err)
							}
						default:
							return "", "", fmt.Errorf("unexpected output format %q", outfmt)
						}
					}
				}
				if len(args) == 2 {
					err = os.WriteFile(s.Path(args[1]), b.Bytes(), 0644)
					if err != nil {
						err = fmt.Errorf("could not write %q: %w", s.Path(args[1]), err)
					}
				} else {
					stdout = b.String()
				}
				return
			}, nil
		},
	)
}
