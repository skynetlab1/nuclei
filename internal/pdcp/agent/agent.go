package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/dustin/go-humanize"
	"github.com/klauspost/compress/zstd"
	"github.com/mackerelio/go-osstat/memory"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/machineid"
	"github.com/projectdiscovery/nuclei/v3/internal/pdcp/agent/client"
	agentproto "github.com/projectdiscovery/nuclei/v3/internal/pdcp/agent/proto"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/batcher"
	"github.com/projectdiscovery/utils/env"
	"github.com/remeh/sizedwaitgroup"
	"google.golang.org/protobuf/proto"
)

var (
	// tm is a manager for nuclei templates
	tm *installer.TemplateManager
)

func init() {
	tm = &installer.TemplateManager{
		CustomTemplates:        nil,
		DisablePublicTemplates: false,
	}
}

var resultsBatcher *batcher.Batcher[[]byte]

// TODO: Figure out dynamic configuration
var globalConfiguration = configuration{
	BulkSize:        10,
	TemplateThreads: 10,
	IsRescan:        false,
}

type ackWorkItem struct {
	ID     string
	ScanID string
}

type noopWriter struct{}

func (n *noopWriter) Write(data []byte, level levels.Level) {}

func freshInstallTemplates() error {
	err := tm.FreshInstallIfNotExists()
	if err != nil {
		return errors.Wrap(err, "could not install nuclei templates")
	}
	installer.NucleiSDKVersionCheck()

	if config.DefaultConfig.NeedsIgnoreFileUpdate() {
		if err := installer.UpdateIgnoreFile(); err != nil {
			gologger.Warning().Msgf("failed to update nuclei ignore file: %s\n", err)
		}
	}
	return nil
}

// TemplatesLock is a global lock for templates
var TemplatesLock *sync.RWMutex

func init() {
	TemplatesLock = &sync.RWMutex{}
}

func updateTemplates() error {
	if err := installer.NucleiVersionCheck(); err != nil {
		slog.Warn("failed to check nuclei version", slog.String("error", err.Error()))
	}
	if config.DefaultConfig.NeedsTemplateUpdate() || config.DefaultConfig.NeedsIgnoreFileUpdate() {
		TemplatesLock.Lock()
		defer TemplatesLock.Unlock()
		if err := tm.UpdateIfOutdated(); err != nil {
			return err
		}
	}
	return nil
}

func updateNucleiTemplatesTicker(d time.Duration, sc <-chan struct{}) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = installer.NucleiVersionCheck()

			if config.DefaultConfig.NeedsIgnoreFileUpdate() {
				if err := installer.UpdateIgnoreFile(); err != nil {
					gologger.Warning().Msgf("failed to update nuclei ignore file: %s\n", err)
				}
			}
			if err := updateTemplates(); err != nil {
				slog.Warn("could not update nuclei templates", slog.String("error", err.Error()))
			}
		case <-sc:
			// Stop the goroutine
			return
		}
	}
}

var (
	isDebug = env.GetEnvOrDefault("DEBUG", true)
)

func newAuroraClient(creds *pdcpauth.PDCPCredentials) (*client.ClientWithResponses, error) {
	// First start by gathering the necessary information
	// about the system and the agent.
	apiKeyProvider, apiKeyProviderErr := securityprovider.NewSecurityProviderApiKey("header", pdcpauth.ApiKeyHeaderName, creds.APIKey)
	if apiKeyProviderErr != nil {
		return nil, errors.Wrap(apiKeyProviderErr, "could not create user key provider")
	}
	var opts []client.ClientOption
	opts = append(opts, client.WithRequestEditorFn(apiKeyProvider.Intercept))
	if isDebug {
		opts = append(opts, client.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			dumped, err := httputil.DumpRequest(req, true)
			if err != nil {
				return err
			}
			gologger.Debug().Msgf("Outgoing request: \n\n%s\n\n", string(dumped))
			return nil
		}))
	}

	auroraClient, err := client.NewClientWithResponses(
		creds.Server,
		opts...,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not create user client")
	}
	return auroraClient, nil
}

// RegisterAgent registers the agent with the server.
func RegisterAgent(creds *pdcpauth.PDCPCredentials) error {
	gologger.Info().Msgf("Installing nuclei-templates and housekeeping\n")

	// Install nuclei-templates, incase they are not installed
	if err := freshInstallTemplates(); err != nil {
		return errors.Wrap(err, "failed to download nuclei-templates")
	}
	// Update nuclei-templates if they are installed and there is a new version
	if err := updateTemplates(); err != nil {
		return errors.Wrap(err, "failed to update nuclei-templates")
	}

	// stop channel for template updater
	sc := make(chan struct{})
	defer close(sc)
	go func() {
		// Update nuclei-templates every 15 minutes
		updateNucleiTemplatesTicker(15*time.Minute, sc)
	}()

	if err := ConfigureNucleiEnvironment(&globalConfiguration); err != nil {
		return errors.Wrap(err, "could not configure nuclei environment")
	}

	gologger.Info().Msgf("Configured nuclei environment\n")

	auroraClient, err := newAuroraClient(creds)
	if err != nil {
		return errors.Wrap(err, "could not create aurora client")
	}

	var agentID *string

	registerAgentFunc := func() error {
		meta, err := gatherAgentMetadata()
		if err != nil {
			return errors.Wrap(err, "could not gather agent metadata")
		}

		resp, err := auroraClient.PostAgentRegisterWithResponse(context.TODO(), client.PostAgentRegisterJSONRequestBody{
			Arch:      meta.Arch,
			CpuCores:  meta.CPU,
			Hostname:  meta.Hostname,
			MachineId: meta.MachineID,
			MemoryGb:  meta.Memory,
			Os:        meta.OS,
		})
		if err != nil {
			return errors.Wrap(err, "could not register agent")
		}
		if resp.JSON200 == nil {
			return fmt.Errorf("could not register agent: %s", string(resp.Body))
		}
		agentID = &resp.JSON200.Id
		return nil
	}
	if err := registerAgentFunc(); err != nil {
		return errors.Wrap(err, "could not register agent")
	}
	gologger.Info().Msgf("Agent registered with id: %s\n", *agentID)

	gologger.Info().Msgf("Starting polling...")
	// Start polling the server for work

	acknowledgeWork := func(ids []ackWorkItem) {

		var agentAckReq []client.AgentAckRequest
		for _, id := range ids {
			agentAckReq = append(agentAckReq, client.AgentAckRequest{
				Id:     id.ID,
				ScanId: id.ScanID,
			})
		}

		// Acknowledge the work
		_, err := auroraClient.PostAgentsIdAckWithResponse(context.TODO(), *agentID, client.PostAgentsIdAckJSONRequestBody(agentAckReq))
		if err != nil {
			gologger.Error().Msgf("could not acknowledge work: %s\n", err)
		}
		gologger.Info().Msgf("Acknowledged work: %v\n", ids)
	}

	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	gologger.DefaultLogger.SetWriter(&noopWriter{})

	resultsBatcher = batcher.New[[]byte](
		batcher.WithMaxCapacity[[]byte](100),
		batcher.WithFlushInterval[[]byte](30*time.Second),
		batcher.WithFlushCallback[[]byte](func(b [][]byte) {
			if len(b) == 0 {
				return
			}

			// Send the results to the server
			res, err := auroraClient.PostAgentsIdResultsWithResponse(context.TODO(), *agentID, client.PostAgentsIdResultsJSONRequestBody(b))
			if err != nil {
				gologger.Error().Msgf("could not send results: %s\n", err)
			} else {
				gologger.Info().Msgf("Sent results: %s = %d\n", string(res.Body), len(b))
			}
		}),
	)
	resultsBatcher.Run()
	defer func() {
		resultsBatcher.Stop()
		resultsBatcher.WaitDone()
	}()

	ackBatcher := batcher.New[ackWorkItem](
		batcher.WithMaxCapacity[ackWorkItem](100),
		batcher.WithFlushInterval[ackWorkItem](30*time.Second),
		batcher.WithFlushCallback[ackWorkItem](func(s []ackWorkItem) {
			if len(s) == 0 {
				return
			}
			acknowledgeWork(s)
		}),
	)
	ackBatcher.Run()
	defer func() {
		ackBatcher.Stop()
		ackBatcher.WaitDone()
	}()

	swg := sizedwaitgroup.New(25)

	iterations := 0
	maxIterations := 5

	// Handle CTRL+C and gracefully shutdown the agent
	// by acknowledging the work and sending the results.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	for {
		select {
		case <-c:
			gologger.Info().Msgf("Shutting down agent...\n")

			_, err := auroraClient.DeleteAgentsIdWithResponse(context.TODO(), *agentID)
			if err != nil {
				gologger.Error().Msgf("could not delete agent: %s\n", err)
			}
			swg.Wait()
			return nil
		default:
			if err := pollAndDoWork(auroraClient, ackBatcher, *agentID, &swg); err != nil {
				if strings.Contains(err.Error(), "could not get local agent") {
					gologger.Info().Msgf("Agent not found, trying to register again\n")

					if err := registerAgentFunc(); err != nil {
						gologger.Error().Msgf("could not register agent: %s, retrtying\n", err)

						iterations++
						if iterations == maxIterations {
							gologger.Error().Msgf("could not register agent after %d attempts: %s\n", maxIterations, err)
							return nil
						}
						time.Sleep(60 * time.Second)
					} else {
						gologger.Info().Msgf("Agent registered with id: %s\n", *agentID)
					}
				}
				gologger.Error().Msgf("could not poll and do work: %s\n", err)
			}
		}
	}
}

var runningWorkers atomic.Int32

var lastPingTimestamp time.Time

func pollAndDoWork(
	auroraClient *client.ClientWithResponses,
	ackBatcher *batcher.Batcher[ackWorkItem],
	agentID string,
	swg *sizedwaitgroup.SizedWaitGroup,
) error {
	workers := runningWorkers.Load()
	var count int
	if workers == 25 {
		time.Sleep(30 * time.Second)
		return nil
	}
	count = 25 - int(workers)

	if count == 0 {
		// Ping the server to keep the connection alive
		// every 30 seconds.
		if time.Since(lastPingTimestamp) >= 30*time.Second {
			_, err := auroraClient.PostAgentsIdPingWithResponse(context.TODO(), agentID)
			if err != nil {
				gologger.Error().Msgf("could not ping agent: %s\n", err)
				return errors.Wrap(err, "could not ping agent")
			}
		}
		return nil
	}
	// Poll the server for work
	resp, err := auroraClient.GetAgentsIdPollWithResponse(context.TODO(), agentID, &client.GetAgentsIdPollParams{
		Count: &count,
	})
	if err != nil {
		return errors.Wrap(err, "could not get agent work")
	}
	lastPingTimestamp = time.Now()
	if resp.JSON200 == nil {
		if resp.JSON500 != nil {
			return fmt.Errorf("%s", string(resp.Body))
		} else {
			gologger.Verbose().Msgf("No work found: %+v\n", string(resp.Body))
		}
		time.Sleep(30 * time.Second)
		return nil
	}

	data := *resp.JSON200
	if len(data) == 0 {
		gologger.Info().Msgf("No work found\n")
		time.Sleep(30 * time.Second)
		return nil
	}

	for _, work := range data {
		work := work

		value, _ := decompressZSTD(work.Value)
		var req agentproto.ScanRequest
		if err := proto.Unmarshal(value, &req); err != nil {
			gologger.Error().Msgf("could not unmarshal scan request: %s\n", err)
			continue
		}

		swg.Add()
		go func(work client.AgentPollTask, req *agentproto.ScanRequest) {
			runningWorkers.Add(1)
			defer swg.Done()
			defer runningWorkers.Add(-1)

			gologger.Info().Msgf("[id:%s] [scan_id:%s] Got work: %v\n", work.Id, work.ScanId, req.String())

			config := globalConfiguration
			config.ScanId = work.ScanId
			if work.ScanConfig != nil {
				config.Config = *work.ScanConfig
			}
			if work.ReportingConfig != nil {
				config.ReportingConfig = *work.ReportingConfig
			}

			if err := ExecuteNucleiScan(context.Background(), req, slog.Default(), &config); err != nil {
				gologger.Error().Msgf("could not execute nuclei scan: %s\n", err)
				return
			}
			ackBatcher.Append(ackWorkItem{
				ID:     work.Id,
				ScanID: work.ScanId,
			})
		}(work, &req)
	}
	if runningWorkers.Load() == 25 {
		time.Sleep(30 * time.Second)
	} else {
		time.Sleep(10 * time.Second)
	}
	return nil
}

type agentMetadata struct {
	MachineID string
	CPU       int
	Memory    int
	OS        string
	Arch      string
	Hostname  string
}

// gatherAgentMetadata gathers the necessary metadata about the agent.
func gatherAgentMetadata() (*agentMetadata, error) {
	meta := &agentMetadata{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
		CPU:  runtime.NumCPU(),
	}

	memoryStats, err := memory.Get()
	if err != nil {
		return nil, errors.Wrap(err, "could not get memory stats")
	}
	meta.Memory = int(math.Ceil(float64(memoryStats.Total) / humanize.GiByte))

	meta.Hostname, err = os.Hostname()
	if err != nil {
		return nil, errors.Wrap(err, "could not get hostname")
	}

	machineID, err := machineid.ProtectedID("pdcp-agent")
	if err != nil {
		return nil, errors.Wrap(err, "could not get machine id")
	}
	meta.MachineID = machineID

	return meta, nil
}

// DecompressZSTD decompresses data using zstd compression
func decompressZSTD(data []byte) ([]byte, error) {
	d, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer d.Close()

	var out bytes.Buffer
	if _, err = io.Copy(&out, d); err != nil {
		return nil, err
	}
	bytesData := out.Bytes()
	return bytesData, nil
}
