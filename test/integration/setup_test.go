package integration

import (
	"context"
	"testing"
	"time"

	"cfgms/pkg/api/proto/controller"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultTimeout = 5 * time.Second
	testAddress    = "localhost:50051"
)

type testEnv struct {
	ctx        context.Context
	cancel     context.CancelFunc
	conn       *grpc.ClientConn
	controller controller.ControllerClient
}

func setupTestEnv(t *testing.T) *testEnv {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)

	// Set up connection to the server
	conn, err := grpc.DialContext(ctx, testAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)

	return &testEnv{
		ctx:        ctx,
		cancel:     cancel,
		conn:       conn,
		controller: controller.NewControllerClient(conn),
	}
}

func (env *testEnv) cleanup() {
	env.cancel()
	env.conn.Close()
}
