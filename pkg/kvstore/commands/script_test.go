// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"context"
	"maps"
	"testing"

	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/time"
)

func TestScript(t *testing.T) {
	setup := func(t testing.TB, args []string) *script.Engine {
		client := kvstore.NewInMemoryClient(statedb.New(), "__local__")
		cmds := TestCommands(client)
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{Cmds: cmds}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{},
		"testdata/*.txtar")
}
