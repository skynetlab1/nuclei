package agent

import (
	"context"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/internal/pdcp/agent/client"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
)

// RunScanOnCloud runs a scan on self-hosted pdcp cloud agent
func RunScanOnCloud(options *types.Options, creds *pdcpauth.PDCPCredentials) error {
	auroraClient, err := newAuroraClient(creds)
	if err != nil {
		return errors.Wrap(err, "could not create aurora client")
	}

	// Create a new scan
	auroraClient.PostV1ScansWithResponse(context.Background(), client.PostV1ScansJSONRequestBody{})
	return nil
}
