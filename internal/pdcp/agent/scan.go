package agent

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/pdcp/agent/client"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
)

// RunScanOnCloud runs a scan on self-hosted pdcp cloud agent
func RunScanOnCloud(options *types.Options, targets, templates []string, creds *pdcpauth.PDCPCredentials) error {
	auroraClient, err := newAuroraClient(creds)
	if err != nil {
		return errors.Wrap(err, "could not create aurora client")
	}

	configuration := getScanConfigFromOptions(options)
	marshalled, err := jsoniter.Marshal(configuration)
	if err != nil {
		return errors.Wrap(err, "could not marshal scan configuration")
	}
	scanConfig := string(marshalled)

	// Create a new scan
	isSelfHosted := true
	resp, err := auroraClient.PostV1ScansWithResponse(context.Background(), client.PostV1ScansJSONRequestBody{
		IsSelfHostedScan: &isSelfHosted,
		Targets:          &targets,
		Templates:        &templates,
		ScanConfig:       &scanConfig,
		Name:             &options.ScanName,
	})
	if err != nil {
		return errors.Wrap(err, "could not create scan")
	}
	if resp.StatusCode() != 200 {
		return errors.Errorf("could not create scan: %s", string(resp.Body))
	}
	if resp.JSON200 == nil || resp.JSON200.Id == nil {
		return errors.New("scan ID not found in response")
	}
	gologger.Info().Msgf("Scan created successfully with ID: %s\n", *resp.JSON200.Id)

	return nil
}

func getScanConfigFromOptions(options *types.Options) *ScanConfiguration {
	config := &ScanConfiguration{
		Authors:           options.Authors,
		Tags:              options.Tags,
		ExcludeTags:       options.ExcludeTags,
		IncludeTags:       options.IncludeTags,
		IncludeIds:        options.IncludeIds,
		ExcludeIds:        options.ExcludeIds,
		IncludeTemplates:  options.IncludeTemplates,
		ExcludedTemplates: options.ExcludedTemplates,
		ExcludeMatchers:   options.ExcludeMatchers,
		IncludeConditions: options.IncludeConditions,
		Headers:           options.CustomHeaders,
		InteractshServer:  options.InteractshURL,
		InteractshToken:   options.InteractshToken,
	}
	for k, v := range options.Vars.AsMap() {
		config.Variables = append(config.Variables, fmt.Sprintf("%s=%s", k, v))
	}
	for _, severity := range options.Severities {
		config.Severities = append(config.Severities, severity.String())
	}
	for _, severity := range options.ExcludeSeverities {
		config.ExcludeSeverities = append(config.ExcludeSeverities, severity.String())
	}
	for _, protocol := range options.Protocols {
		config.Protocols = append(config.Protocols, protocol.String())
	}
	for _, excludeProtocol := range options.ExcludeProtocols {
		config.ExcludeProtocols = append(config.ExcludeProtocols, excludeProtocol.String())
	}
	return config
}
