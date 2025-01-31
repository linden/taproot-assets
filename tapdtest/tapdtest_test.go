package tapdtest

import (
	"context"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcdtest"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lndtest"
	"github.com/stretchr/testify/require"
)

func TestHarness(t *testing.T) {
	btcd := btcdtest.New()
	defer btcd.Stop()

	_, err := btcd.Generate(300)
	if err != nil {
		t.Fatal(err)
	}

	lnd := lndtest.New(
		lndtest.WithBtcd(btcd),
	)
	defer lnd.Stop()

	tap := New(
		WithLND(lnd),
		WithDir(t.TempDir()),
		WithOutput(os.Stderr, os.Stdout),
	)
	defer tap.Close()

	tc := taprpc.NewTaprootAssetsClient(tap)

	info, err := tc.GetInfo(context.TODO(), &taprpc.GetInfoRequest{})
	require.NoError(t, err)

	t.Logf("info: %+v\n", info)
}
