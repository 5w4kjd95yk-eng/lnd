package healthcheck

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/lightningnetwork/lnd/tor"
	"github.com/stretchr/testify/require"
)

func TestShouldReconnectForConnectionError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		reconnect bool
	}{
		{
			name:      "broken pipe",
			err:       syscall.EPIPE,
			reconnect: true,
		},
		{
			name:      "closed connection",
			err:       net.ErrClosed,
			reconnect: true,
		},
		{
			name: "wrapped closed connection",
			err: errors.Join(errors.New("check failed"),
				net.ErrClosed),
			reconnect: true,
		},
		{
			name: "end of file",
			err:  io.EOF,
		},
		{
			name: "unrelated error",
			err:  errors.New("unknown response"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.reconnect,
				shouldReconnectForConnectionError(test.err))
		})
	}
}

func TestShouldReconnectForServiceError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		reconnect bool
	}{
		{
			name:      "service ID mismatch",
			err:       tor.ErrServiceIDMismatch,
			reconnect: true,
		},
		{
			name:      "missing services",
			err:       tor.ErrNoServiceFound,
			reconnect: true,
		},
		{
			name:      "services inactive",
			err:       tor.ErrServiceNotCreated,
			reconnect: true,
		},
		{
			name: "wrapped mismatch",
			err: errors.Join(errors.New("restore failed"),
				tor.ErrServiceIDMismatch),
			reconnect: true,
		},
		{
			name: "connection error",
			err:  io.EOF,
		},
		{
			name: "unrelated error",
			err:  errors.New("unknown response"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.reconnect,
				shouldReconnectForServiceError(test.err))
		})
	}
}
