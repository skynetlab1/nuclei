package agent

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/es"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/splunk"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/github"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/gitlab"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/jira"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"gopkg.in/yaml.v2"
)

// ScanConfiguration is a configuration for a scan
type ScanConfiguration struct {
	Authors           []string `yaml:"author,omitempty"`
	Tags              []string `yaml:"tags,omitempty"`
	ExcludeTags       []string `yaml:"exclude-tags,omitempty"`
	IncludeTags       []string `yaml:"include-tags,omitempty"`
	IncludeIds        []string `yaml:"template-id,omitempty"`
	ExcludeIds        []string `yaml:"exclude-id,omitempty"`
	IncludeTemplates  []string `yaml:"include-templates,omitempty"`
	ExcludedTemplates []string `yaml:"exclude-templates,omitempty"`
	ExcludeMatchers   []string `yaml:"exclude-matchers,omitempty"`
	Severities        []string `yaml:"severity,omitempty"`
	ExcludeSeverities []string `yaml:"exclude-severity,omitempty"`
	Protocols         []string `yaml:"type,omitempty"`
	ExcludeProtocols  []string `yaml:"exclude-type,omitempty"`
	IncludeConditions []string `yaml:"template-condition,omitempty"`
	Headers           []string `yaml:"header,omitempty"`
	Variables         []string `yaml:"var,omitempty"`
	InteractshServer  string   `yaml:"interactsh-server,omitempty"`
	InteractshToken   string   `yaml:"interactsh-token,omitempty"`
}

// MergeScanConfiguration merges other into s
func (s *ScanConfiguration) MergeScanConfiguration(other *ScanConfiguration) {
	s.Authors = mergeStringSliceUnique(s.Authors, other.Authors)
	s.Tags = mergeStringSliceUnique(s.Tags, other.Tags)
	s.ExcludeTags = mergeStringSliceUnique(s.ExcludeTags, other.ExcludeTags)
	s.IncludeTags = mergeStringSliceUnique(s.IncludeTags, other.IncludeTags)
	s.IncludeIds = mergeStringSliceUnique(s.IncludeIds, other.IncludeIds)
	s.ExcludeIds = mergeStringSliceUnique(s.ExcludeIds, other.ExcludeIds)
	s.IncludeTemplates = mergeStringSliceUnique(s.IncludeTemplates, other.IncludeTemplates)
	s.ExcludedTemplates = mergeStringSliceUnique(s.ExcludedTemplates, other.ExcludedTemplates)
	s.ExcludeMatchers = mergeStringSliceUnique(s.ExcludeMatchers, other.ExcludeMatchers)
	s.Severities = mergeStringSliceUnique(s.Severities, other.Severities)
	s.ExcludeSeverities = mergeStringSliceUnique(s.ExcludeSeverities, other.ExcludeSeverities)
	s.Protocols = mergeStringSliceUnique(s.Protocols, other.Protocols)
	s.ExcludeProtocols = mergeStringSliceUnique(s.ExcludeProtocols, other.ExcludeProtocols)
	s.IncludeConditions = mergeStringSliceUnique(s.IncludeConditions, other.IncludeConditions)
	s.Headers = mergeStringSliceUnique(s.Headers, other.Headers)
	if s.InteractshServer == "" && other.InteractshServer != "" {
		s.InteractshServer = other.InteractshServer
	}
	if s.InteractshToken == "" && other.InteractshToken != "" {
		s.InteractshToken = other.InteractshToken
	}
	s.Variables = mergeStringSliceUnique(s.Variables, other.Variables)
}

// Encode returns a base64 encoded representation of the configuration
func (s *ScanConfiguration) Encode() (string, error) {
	var buffer bytes.Buffer
	if err := yaml.NewEncoder(&buffer).Encode(s); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buffer.Bytes()), nil
}

func mergeStringSliceUnique(s1, s2 []string) []string {
	uniq := make(map[string]struct{})

	for _, s := range s1 {
		uniq[s] = struct{}{}
	}
	for _, s := range s2 {
		uniq[s] = struct{}{}
	}

	results := make([]string, 0, len(uniq))
	for s := range uniq {
		results = append(results, s)
	}
	return results
}

// GetFilter returns a tag filter for the scan configuration
func (s *ScanConfiguration) GetFilter() (*templates.TagFilter, error) {
	cfg := &templates.TagFilterConfig{
		Tags:              s.Tags,
		ExcludeTags:       s.ExcludeIds,
		Authors:           s.Authors,
		IncludeTags:       s.IncludeTags,
		IncludeIds:        s.IncludeIds,
		ExcludeIds:        s.ExcludeIds,
		IncludeConditions: s.IncludeConditions,
	}
	for _, opt := range s.Severities {
		_ = cfg.Severities.Set(opt)
	}
	for _, opt := range s.ExcludeSeverities {
		_ = cfg.ExcludeSeverities.Set(opt)
	}
	for _, opt := range s.Protocols {
		_ = cfg.Protocols.Set(opt)
	}
	for _, opt := range s.ExcludeProtocols {
		_ = cfg.ExcludeProtocols.Set(opt)
	}

	tagFilter, err := templates.NewTagFilter(cfg)
	if err != nil {
		return nil, err
	}
	return tagFilter, nil
}

// MergeOptions merges the scan configuration with the options
// for a nuclei scanner
func (s *ScanConfiguration) MergeOptions(options *types.Options) {
	options.Authors = append(options.Authors, s.Authors...)
	options.Tags = append(options.Tags, s.Tags...)
	options.ExcludeTags = append(options.ExcludeTags, s.ExcludeTags...)
	options.IncludeTags = append(options.IncludeTags, s.IncludeTags...)
	options.IncludeIds = append(options.IncludeIds, s.IncludeIds...)
	options.ExcludeIds = append(options.ExcludeIds, s.ExcludeIds...)
	options.IncludeTemplates = append(options.IncludeTemplates, s.IncludeTemplates...)
	options.ExcludedTemplates = append(options.ExcludedTemplates, s.ExcludedTemplates...)
	options.ExcludeMatchers = append(options.ExcludeMatchers, s.ExcludeMatchers...)
	options.IncludeConditions = append(options.IncludeConditions, s.IncludeConditions...)
	options.InteractshURL = s.InteractshServer
	options.InteractshToken = s.InteractshToken

	for _, opt := range s.Severities {
		_ = options.Severities.Set(opt)
	}
	for _, opt := range s.ExcludeSeverities {
		_ = options.ExcludeSeverities.Set(opt)
	}
	for _, opt := range s.Protocols {
		_ = options.Protocols.Set(opt)
	}
	for _, opt := range s.ExcludeProtocols {
		_ = options.ExcludeProtocols.Set(opt)
	}
	for _, opt := range s.Headers {
		_ = options.CustomHeaders.Set(opt)
	}
	for _, opt := range s.Variables {
		_ = options.Vars.Set(opt)
	}
}

// ReadConfig reads a base64 encoded config and returns
// ScanConfiguration structure
func readConfig(configEncoded string) (*ScanConfiguration, error) {
	configuration := &ScanConfiguration{}

	decoded, err := base64.StdEncoding.DecodeString(configEncoded)
	if err != nil {
		return nil, err
	}
	if err := yaml.NewDecoder(bytes.NewReader(decoded)).Decode(configuration); err != nil {
		return nil, err
	}
	return configuration, nil
}

type reportingOptionFilter struct {
	Severities []string `yaml:"severity"`
	Tags       []string `yaml:"tags"`
}

// ReportingOptions is a configuration file for nuclei reporting module
type ReportingOptions struct {
	// AllowList contains a list of allowed events for reporting module
	AllowList *reportingOptionFilter `yaml:"allow-list"`
	// DenyList contains a list of denied events for reporting module
	DenyList *reportingOptionFilter `yaml:"deny-list"`
	// GitHub contains configuration options for GitHub Issue Tracker
	GitHub *github.Options `yaml:"github"`
	// GitLab contains configuration options for GitLab Issue Tracker
	GitLab *gitlab.Options `yaml:"gitlab"`
	// Jira contains configuration options for Jira Issue Tracker
	Jira *jira.Options `yaml:"jira"`
	// ElasticsearchExporter contains configuration options for Elasticsearch Exporter Module
	ElasticsearchExporter *es.Options `yaml:"elasticsearch"`
	// SplunkExporter contains configuration options for splunkhec Exporter Module
	SplunkExporter *splunk.Options `yaml:"splunkhec"`
}

func (r ReportingOptions) ProviderName() string {
	if r.GitHub != nil {
		return "github"
	}
	if r.GitLab != nil {
		return "gitlab"
	}
	if r.Jira != nil {
		return "jira"
	}
	if r.ElasticsearchExporter != nil {
		return "elasticsearch"
	}
	if r.SplunkExporter != nil {
		return "splunkhec"
	}
	return ""
}

// Encode returns a base64 encoded representation of the configuration
func (c *ReportingOptions) Encode() (string, error) {
	var buffer bytes.Buffer
	if err := yaml.NewEncoder(&buffer).Encode(c); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buffer.Bytes()), nil
}

func (c *ReportingOptions) MergeReportingConfiguration(other *ReportingOptions) error {
	if c.SplunkExporter != nil && other.SplunkExporter != nil {
		return errors.New("only one splunkhec report configuration allowed per scan.")
	}
	if c.ElasticsearchExporter != nil && other.ElasticsearchExporter != nil {
		return errors.New("only one elasticsearch report configuration allowed per scan.")
	}
	if c.Jira != nil && other.Jira != nil {
		return errors.New("only one jira report configuration allowed per scan.")
	}
	if c.GitLab != nil && other.GitLab != nil {
		return errors.New("only one gitlab report configuration allowed per scan.")
	}
	if c.GitHub != nil && other.GitHub != nil {
		return errors.New("only one github report configuration allowed per scan.")
	}
	if c.SplunkExporter == nil && other.SplunkExporter != nil {
		c.SplunkExporter = other.SplunkExporter
	}
	if c.ElasticsearchExporter == nil && other.ElasticsearchExporter != nil {
		c.ElasticsearchExporter = other.ElasticsearchExporter
	}
	if c.Jira == nil && other.Jira != nil {
		c.Jira = other.Jira
	}
	if c.GitLab == nil && other.GitLab != nil {
		c.GitLab = other.GitLab
	}
	if c.GitHub == nil && other.GitHub != nil {
		c.GitHub = other.GitHub
	}
	if c.AllowList == nil && other.AllowList != nil {
		c.AllowList = other.AllowList
	} else if c.AllowList != nil && other.AllowList != nil {
		c.AllowList = mergeFilters(c.AllowList, other.AllowList)
	}
	if c.DenyList == nil && other.DenyList != nil {
		c.DenyList = other.DenyList
	} else if c.DenyList != nil && other.DenyList != nil {
		c.DenyList = mergeFilters(c.DenyList, other.DenyList)
	}
	return nil
}

func mergeFilters(first *reportingOptionFilter, second *reportingOptionFilter) *reportingOptionFilter {
	finalSeverities := mergeStringSliceUnique(first.Severities, second.Severities)
	finalTags := mergeStringSliceUnique(first.Tags, second.Tags)

	combined := &reportingOptionFilter{
		Severities: finalSeverities,
		Tags:       finalTags,
	}
	return combined
}

// readReportingConfig reads a reporting configuration from a file
func readReportingConfig(configEncoded string) (*ReportingOptions, error) {
	options := &ReportingOptions{}

	decoded, err := base64.StdEncoding.DecodeString(configEncoded)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(decoded, options)
	if err != nil {
		return nil, err
	}
	return options, nil
}

func (c *ReportingOptions) GetReportingCfg() *reporting.Options {
	var allowList, denyList *filters.Filter

	if c.AllowList != nil {
		allowList = &filters.Filter{}
		if len(c.AllowList.Tags) > 0 {
			allowList.Tags = stringslice.New(c.AllowList.Tags)
		}
		if len(c.AllowList.Severities) > 0 {
			allowList.Severities = severity.Severities{}
			for _, severity := range c.AllowList.Severities {
				_ = allowList.Severities.Set(severity)
			}
		}
	}
	if c.DenyList != nil {
		denyList = &filters.Filter{}
		if len(c.DenyList.Tags) > 0 {
			denyList.Tags = stringslice.New(c.DenyList.Tags)
		}
		if len(c.DenyList.Severities) > 0 {
			denyList.Severities = severity.Severities{}
			for _, severity := range c.DenyList.Severities {
				_ = denyList.Severities.Set(severity)
			}
		}
	}
	return &reporting.Options{
		AllowList:             allowList,
		DenyList:              denyList,
		GitHub:                c.GitHub,
		GitLab:                c.GitLab,
		Jira:                  c.Jira,
		ElasticsearchExporter: c.ElasticsearchExporter,
		SplunkExporter:        c.SplunkExporter,
	}
}
