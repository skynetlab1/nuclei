package agent

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"github.com/jackc/pgx/v5/pgtype"
	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/internal/pdcp/agent/proto"
	nucleiConfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	nucleiReporting "github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	nucleiTypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/ratelimit"
	"github.com/rs/xid"
)

var (
	initOnce sync.Once

	httpxClient   *httpx.HTTPX
	httpxBulkSize int
)

type configuration struct {
	BulkSize        int
	TemplateThreads int
	InteractshURL   string
	InteractshToken string
	IsRescan        bool
	ScanId          string
	Config          string
	ReportingConfig string
}

// ConfigureNucleiEnvironment configures the nuclei environment.
func ConfigureNucleiEnvironment(configuration *configuration) error {
	defaultNucleiOpts := newDefaultNucleiOptions(configuration)

	htCl, bsSize, err := createHTTPXClient(defaultNucleiOpts)
	if err != nil {
		return errors.Wrap(err, "could not create httpx client")
	}
	httpxClient = htCl
	httpxBulkSize = bsSize

	_ = protocolstate.Init(defaultNucleiOpts)
	_ = protocolinit.Init(defaultNucleiOpts)
	return nil
}

func firstTimeInit(req *proto.ScanRequest, configuration *configuration) {
	defaultNucleiOpts := newDefaultNucleiOptions(configuration)
	if req.IsRescan {
		defaultNucleiOpts.MatcherStatus = true
	}
	_ = protocolstate.Init(defaultNucleiOpts)
	_ = protocolinit.Init(defaultNucleiOpts)
}

// ExecuteNucleiScan executes a nuclei scan on a proto.ScanRequest
func ExecuteNucleiScan(
	ctx context.Context,
	req *proto.ScanRequest,
	l *slog.Logger,
	configuration *configuration,
) error {
	initOnce.Do(func() {
		firstTimeInit(req, configuration)
	})

	var templatesList []string
	for template := range req.PublicTemplates {
		templatesList = append(templatesList, template)
	}

	err := runNucleiScan(
		ctx, req, templatesList, l, configuration)

	if err != nil {
		return errors.Wrap(err, "could not run nuclei scan")
	}
	return nil
}

const (
	DefaultMaxHostCount = 30
)

// runNucleiScan runs the nuclei scan
func runNucleiScan(
	ctx context.Context,
	req *proto.ScanRequest,
	templateList []string,
	l *slog.Logger,
	configuration *configuration,
) error {
	outputWriter := testutils.NewMockOutputWriter(true)
	privateTemplateIDToContents := make(map[string]string)
	templateIDToTemplateURL := make(map[string]string)

	outputWriter.WriteCallback = func(event *output.ResultEvent) {

		vulnHash := calculateVulnHashFromMatch(event)

		result := &pdcpResult{
			ScanID:        configuration.ScanId,
			Event:         event,
			MatcherStatus: true,
			UserID:        req.UserID,
			Severity:      event.Info.SeverityHolder.Severity.String(),
			Tags:          event.Info.Tags.ToSlice(),
		}
		if event.Host != "" {
			result.Host = pgtype.Text{String: event.Host, Valid: true}
		}
		if event.TemplateID != "" {
			if len(templateIDToTemplateURL) == 0 {
				if contents, ok := privateTemplateIDToContents[event.TemplateID]; ok {
					result.TemplateEncoded = contents
				}
			}
			if url, ok := templateIDToTemplateURL[event.TemplateID]; ok {
				result.TemplateUrl = url
			}
			if len(req.PublicTemplates) > 0 {
				result.TemplateUrl = fmt.Sprintf("https://cloud.projectdiscovery.io/public/%s", event.TemplateID)
			}
		}
		result.Target = strings.TrimSuffix(event.Host, ".")
		result.ID = xid.New().String()
		result.VulnHash = vulnHash

		l.Debug("Got result", slog.String("result", fmt.Sprint(result.Event.Info.Name, result.Event.Host)))

		data, err := jsoniter.Marshal(result)
		if err != nil {
			l.Error(errors.Wrap(err, "could not marshal output").Error())
			return
		}
		resultsBatcher.Append(data)
	}

	var maxHostCount int
	// applies optimization
	switch req.Optimization {
	case proto.OptimizationType_FAST_HTTP:
		maxHostCount = 10
	case proto.OptimizationType_FAST_NETWORK:
		maxHostCount = 2
	default:
		maxHostCount = DefaultMaxHostCount
	}

	nucleiOptions := getNucleiOptions(configuration)
	if configuration.Config != "" {
		decoded, err := readConfig(configuration.Config)
		if err != nil {
			l.Error(errors.Wrap(err, "could not read config file").Error())
		} else {
			decoded.MergeOptions(nucleiOptions)
		}
	}

	nucleiOptions.Templates = templateList
	nucleiOptions.MaxHostError = maxHostCount
	mockProgress := &testutils.MockProgressClient{}
	interactOpts := interactsh.DefaultOptions(outputWriter, nil, mockProgress)
	if nucleiOptions.InteractshURL != "" {
		interactOpts.ServerURL = nucleiOptions.InteractshURL
		interactOpts.Authorization = nucleiOptions.InteractshToken
	} else if configuration.InteractshURL != "" && configuration.InteractshToken != "" {
		interactOpts.ServerURL = configuration.InteractshURL
		interactOpts.Authorization = configuration.InteractshToken
	}
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		return errors.Wrap(err, "could not create interactsh client")
	}

	// This assumes that the templates are downloaded to /nuclei-templates
	templatesDirectory := nucleiConfig.DefaultConfig.GetTemplateDir()

	var reportingClient nucleiReporting.Client
	if configuration.ReportingConfig != "" {
		rcCfg, err := readReportingConfig(configuration.ReportingConfig)
		if err != nil {
			return errors.Wrap(err, "could not read reporting config file")
		}
		rc, err := nucleiReporting.New(rcCfg.GetReportingCfg(), "", true)
		if err != nil {
			return errors.Wrap(err, "could not create reporting client")
		}
		reportingClient = rc
	}
	executerOpts := protocols.ExecutorOptions{
		Output:          outputWriter,
		Options:         nucleiOptions,
		Progress:        mockProgress,
		Catalog:         disk.NewCatalog(templatesDirectory),
		RateLimiter:     ratelimit.New(context.Background(), uint(nucleiOptions.RateLimit), time.Second),
		Interactsh:      interactClient,
		HostErrorsCache: hosterrorscache.New(10, hosterrorscache.DefaultMaxHostsCount, nil),
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       nucleiTypes.NewResumeCfg(),
		DoNotCache:      true,
		Parser:          templates.NewParser(),
		//	Browser:         headlessBrowser,
	}
	if reportingClient != nil {
		executerOpts.IssuesClient = reportingClient
	}
	workflowLoader, err := workflow.NewLoader(&executerOpts)
	if err != nil {
		return errors.Wrap(err, "could not create workflow loader")
	}
	executerOpts.WorkflowLoader = workflowLoader

	engine := core.New(nucleiOptions)
	engine.SetExecuterOptions(executerOpts)

	var storeTemplates []*templates.Template

	// Load public templates from disk using a loader
	if len(templateList) > 0 {
		store, err := loader.New(loader.NewConfig(nucleiOptions, executerOpts.Catalog, executerOpts))
		if err != nil {
			return errors.Wrap(err, "could not create loader")
		}
		store.Load()

		storeTemplates = store.Templates()
		l.Debug(fmt.Sprintf("loaded %+v public templates: %+v", len(storeTemplates), storeTemplates))
	}

	// Load private templates as well if any
	if len(req.PrivateTemplates) > 0 {
		for name, contents := range req.PrivateTemplates {
			decoded, err := base64.StdEncoding.DecodeString(contents)
			if err != nil {
				l.Warn(errors.Wrap(err, "could not decode private template").Error())
				continue
			}
			parsed, err := templates.ParseTemplateFromReader(bytes.NewReader(decoded), nil, executerOpts.Copy())
			if err != nil {
				l.Warn(errors.Wrap(err, "could not parse private template").Error())
				continue
			}
			if parsed == nil {
				l.Warn(fmt.Sprint("could not parse private template => ", name))
				continue
			}
			// We do not allow running workflows with private
			// templates.
			if len(parsed.Workflows) > 0 || parsed.CompiledWorkflow != nil {
				continue
			}
			privateTemplateIDToContents[parsed.ID] = contents
			parsed.Path = name
			storeTemplates = append(storeTemplates, parsed)

			if req.TemplateURLs[name] != "" {
				templateIDToTemplateURL[parsed.ID] = req.TemplateURLs[name]
			}
		}
		l.Debug(fmt.Sprintf("loaded %d private templates: %+v", len(req.PrivateTemplates), req.PrivateTemplates))
	}

	if len(req.TemplateURLs) > 0 {
		l.Debug(fmt.Sprintf("loaded %d template URLs: %+v", len(req.TemplateURLs), req.TemplateURLs))
	}

	if len(storeTemplates) == 0 {
		return errors.Wrap(err, "could not load templates")
	}

	input, err := initializeTemplatesHTTPInput(httpxBulkSize, httpxClient, req)
	if err != nil {
		return errors.Wrap(err, "could not initialize templates http input")
	}

	l.Info("started nuclei scan request",
		slog.Int("targets", len(req.Targets)),
		slog.Int("public_templates", len(nucleiOptions.Templates)),
		slog.Int("private_templates", len(req.PrivateTemplates)),
		slog.Int("template_urls", len(req.TemplateURLs)))

	_ = engine.Execute(ctx, storeTemplates, input)

	executerOpts.HostErrorsCache.Close()
	executerOpts.Interactsh.Close()
	executerOpts.RateLimiter.Stop()
	outputWriter.Close()
	//headlessBrowser.Close()

	return nil
}

// getNucleiOptions returns default options for nuclei
func getNucleiOptions(configuration *configuration) *nucleiTypes.Options {
	options := &nucleiTypes.Options{
		RateLimit:                  configuration.BulkSize * configuration.TemplateThreads,
		BulkSize:                   configuration.BulkSize,        // number of targets to elaborate per template
		TemplateThreads:            configuration.TemplateThreads, // number of templates to run in parallel
		HeadlessBulkSize:           10,                            // cannot run headless as of now
		HeadlessTemplateThreads:    10,                            // cannot run headless as of now
		Timeout:                    10,
		Retries:                    1,
		MaxHostError:               30,
		AllowLocalFileAccess:       false,
		RestrictLocalNetworkAccess: true,
		JSONRequests:               true,
		PageTimeout:                20,
		ResponseReadSize:           10 * 1024 * 1024,
		ResponseSaveSize:           1 * 1024 * 1024,
	}
	if configuration.InteractshURL != "" && configuration.InteractshToken != "" {
		options.InteractshURL = configuration.InteractshURL
		options.InteractshToken = configuration.InteractshToken
	}
	return options
}

func newDefaultNucleiOptions(configuration *configuration) *nucleiTypes.Options {
	nucleiOptions := &nucleiTypes.Options{
		RateLimit:                  configuration.BulkSize * configuration.TemplateThreads,
		BulkSize:                   configuration.BulkSize,        // number of targets to elaborate per template
		TemplateThreads:            configuration.TemplateThreads, // number of templates to run in parallel
		HeadlessBulkSize:           10,                            // cannot run headless as of now
		HeadlessTemplateThreads:    10,                            // cannot run headless as of now
		Timeout:                    10,
		Retries:                    1,
		MaxHostError:               30,
		AllowLocalFileAccess:       false,
		RestrictLocalNetworkAccess: true,
		JSONRequests:               true,
		PageTimeout:                20,
		ResponseReadSize:           10 * 1024 * 1024,
		ResponseSaveSize:           1 * 1024 * 1024,
		MatcherStatus:              configuration.IsRescan,
	}
	return nucleiOptions
}

const probeBulkSize = 50

// createHTTPXClient creates a new httpx client for use in nuclei
func createHTTPXClient(options *nucleiTypes.Options) (*httpx.HTTPX, int, error) {
	var bulkSize = probeBulkSize
	if options.BulkSize > probeBulkSize {
		bulkSize = options.BulkSize
	}

	httpxOptions := httpx.DefaultOptions
	httpxOptions.RetryMax = options.Retries
	httpxOptions.Timeout = time.Duration(options.Timeout) * time.Second
	httpxClient, err := httpx.New(&httpxOptions)
	if err != nil {
		return nil, 0, errors.Wrap(err, "could not create httpx client")
	}
	return httpxClient, bulkSize, nil
}

// initializeTemplatesHTTPInput initializes the http form of input
// for any loaded http templates if input is in non-standard format.
func initializeTemplatesHTTPInput(bulkSize int, httpxClient *httpx.HTTPX, req *proto.ScanRequest) (*provider.SimpleInputProvider, error) {
	// Probe the non-standard URLs and store them in cache
	swg := sizedwaitgroup.New(bulkSize)

	final := &provider.SimpleInputProvider{}
	for input := range req.Targets {
		handleInput(input, &swg, httpxClient, final)
	}
	swg.Wait()

	return final, nil
}

func handleInput(input string, swg *sizedwaitgroup.SizedWaitGroup, httpxClient *httpx.HTTPX, results *provider.SimpleInputProvider) {
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		results.Set(input)
		return
	}

	swg.Add()
	go func(input string) {
		defer swg.Done()

		if result := probeURL(input, httpxClient); result != "" {
			results.Set(result)
		}
	}(input)
}

var (
	httpSchemes = []string{"https", "http"}
)

// probeURL probes the scheme for a URL. first HTTPS is tried
// and if any errors occur http is tried. If none succeeds, probing
// is abandoned for such URLs.
func probeURL(input string, httpxclient *httpx.HTTPX) string {
	for _, scheme := range httpSchemes {
		formedURL := fmt.Sprintf("%s://%s", scheme, input)
		req, err := httpxclient.NewRequest(http.MethodHead, formedURL)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", uarand.GetRandom())

		if _, err = httpxclient.Do(req, httpx.UnsafeOptions{}); err != nil {
			continue
		}
		return formedURL
	}
	return ""
}

func extractURLFromHTTPRequest(baseURL, req string) string {
	// Get the first line and extract the URL from it
	lines := strings.SplitN(req, "\n", 2)
	if len(lines) == 0 {
		return baseURL
	}
	line := lines[0]

	// Extract the URL from the line
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return baseURL
	}

	if strings.HasPrefix(parts[1], "http://") || strings.HasPrefix(parts[1], "https://") {
		return parts[1]
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	parsedURL.Path = path.Join(parsedURL.Path, parts[1])
	formedURL := parsedURL.String()
	return formedURL
}

// calculateVulnHashFromMatch calculates a hash from a match
func calculateVulnHashFromMatch(event *output.ResultEvent) string {
	hasher := md5.New()

	// If the matcher didn't match, we need to calculate the matched
	// field value because nuclei sends it to us as empty string
	if !event.MatcherStatus {
		if event.Type == "http" {
			if event.Matched = extractURLFromHTTPRequest(event.URL, event.Request); event.Matched == "" {
				event.Matched = event.URL
			}
		} else {
			event.Matched = event.Host
		}
	}
	// If we have http and a url pattern specified, we need to remove dynamic
	// elements from the pattern.
	if event.Type == "http" && event.ReqURLPattern != "" && strings.Contains(event.ReqURLPattern, "{{") {
		// Write the function to identify placeholders and replace URL with static
		// values that are dynamic from the pattern
		parsed, err := url.Parse(event.Matched)
		if err != nil {
			hasher.Write([]byte(event.Matched))
		} else {
			finalURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, event.ReqURLPattern)
			hasher.Write([]byte(finalURL))
		}
	} else {
		hasher.Write([]byte(event.Matched))
	}

	hasher.Write([]byte(event.TemplateID))
	if event.MatcherName != "" {
		_, _ = hasher.Write([]byte(event.MatcherName))
	}
	if event.ExtractorName != "" {
		_, _ = hasher.Write([]byte(event.ExtractorName))
	}
	if event.ExtractedResults != nil {
		for _, extracted := range event.ExtractedResults {
			_, _ = hasher.Write([]byte(extracted))
		}
	}

	encoded := hex.EncodeToString(hasher.Sum(nil))
	return encoded
}

type pdcpResult struct {
	ID              string              `json:"id"`
	ScanID          string              `json:"scan_id"`
	UserID          int64               `json:"user_id"`
	Target          string              `json:"target"`
	VulnStatus      string              `json:"vuln_status"`
	TemplateEncoded string              `json:"template_encoded"`
	TemplateUrl     string              `json:"template_url"`
	VulnHash        string              `json:"vuln_hash"`
	MatcherStatus   bool                `json:"matcher_status"`
	Event           *output.ResultEvent `json:"event"`
	CreatedAt       pgtype.Timestamp    `json:"created_at"`
	UpdatedAt       pgtype.Timestamp    `json:"updated_at"`
	Severity        string              `json:"severity"`
	Tags            []string            `json:"tags"`
	Host            pgtype.Text         `json:"host"`
}
