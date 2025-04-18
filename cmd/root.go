package cmd

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Method-Security/pkg/signal"
	"github.com/Method-Security/pkg/writer"
	"github.com/method-security/methodokta/internal/config"
	"github.com/okta/okta-sdk-golang/v5/okta"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

type MethodOkta struct {
	version      string
	RootFlags    config.RootFlags
	OktaConfig   *okta.Configuration
	RequestSleep time.Duration
	OutputConfig writer.OutputConfig
	OutputSignal signal.Signal
	RootCmd      *cobra.Command
}

func NewMethodOkta(version string) *MethodOkta {
	startedAt := datetime.DateTime(time.Now())
	methodOkta := MethodOkta{
		version: version,
		RootFlags: config.RootFlags{
			Quiet:   false,
			Verbose: false,
			Limit:   0,
			OktaAuth: config.OktaAuth{
				Domain:   "",
				APIToken: "",
			},
		},
		RequestSleep: 10 * time.Second,
		OutputConfig: writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL)),
		OutputSignal: signal.NewSignal(nil, &startedAt, nil, 0, nil),
	}
	return &methodOkta
}

func (a *MethodOkta) InitRootCommand() {
	var outputFormat string
	var outputFile string
	a.RootCmd = &cobra.Command{
		Use:          "methodokta",
		Short:        "Audit Okta resources",
		Long:         `Audit Okta resources`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error

			format, err := validateOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var outputFilePointer *string
			if outputFile != "" {
				outputFilePointer = &outputFile
			} else {
				outputFilePointer = nil
			}
			a.OutputConfig = writer.NewOutputConfig(outputFilePointer, format)
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags)))

			// Okta Configuration
			config, err := getOktaConfig(a)
			if err != nil {
				return err
			}
			a.OktaConfig = config

			return nil
		},

		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			completedAt := datetime.DateTime(time.Now())
			a.OutputSignal.CompletedAt = &completedAt
			return writer.Write(
				a.OutputSignal.Content,
				a.OutputConfig,
				&a.OutputSignal.StartedAt,
				a.OutputSignal.CompletedAt,
				a.OutputSignal.Status,
				a.OutputSignal.ErrorMessage,
			)
		},
	}

	// Standard flags
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Quiet, "quiet", "q", false, "Suppress output")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Verbose, "verbose", "v", false, "Verbose output")
	a.RootCmd.PersistentFlags().StringVarP(&outputFile, "output-file", "f", "", "Path to output file. If blank, will output to STDOUT")
	a.RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "signal", "Output format (signal, json, yaml). Default value is signal")

	//OktaConfig Flags
	a.RootCmd.PersistentFlags().StringVarP(&a.RootFlags.OktaAuth.APIToken, "apitoken", "a", "", "Okta API Token")
	a.RootCmd.PersistentFlags().StringVarP(&a.RootFlags.OktaAuth.Domain, "domain", "d", "", "Okta Domain (ie. https://myokta.okta.com)")
	a.RootCmd.PersistentFlags().IntVarP(&a.RootFlags.Limit, "limit", "l", 0, "Upper Bound for returned objects")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of methodokta",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(a.version)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
	}

	a.RootCmd.AddCommand(versionCmd)
}

// A utility function to validate that the provided output format is one of the supported formats: json, yaml, signal.
func validateOutputFormat(output string) (writer.Format, error) {
	var format writer.FormatValue
	switch strings.ToLower(output) {
	case "json":
		format = writer.JSON
	case "yaml":
		return writer.Format{}, errors.New("yaml output format is not supported for methodokta")
	case "signal":
		format = writer.SIGNAL
	default:
		return writer.Format{}, errors.New("invalid output format. Valid formats are: json, yaml, signal")
	}
	return writer.NewFormat(format), nil
}

func getOktaConfig(a *MethodOkta) (*okta.Configuration, error) {
	// Get Domain
	domain := ""
	if a.RootFlags.OktaAuth.Domain != "" {
		domain = a.RootFlags.OktaAuth.Domain
	} else if len(os.Getenv("OKTA_DOMAIN")) != 0 {
		domain = os.Getenv("OKTA_DOMAIN")
	} else {
		err := errors.New("please provide a Okta domain either by flag or ENV variable")
		return nil, err
	}

	//Get API Token
	apiToken := ""
	if a.RootFlags.OktaAuth.APIToken != "" {
		apiToken = a.RootFlags.OktaAuth.APIToken
	} else if len(os.Getenv("OKTA_API_TOKEN")) != 0 {
		apiToken = os.Getenv("OKTA_API_TOKEN")
	} else {
		err := errors.New("please provide an API Token either by flag or ENV variable")
		return nil, err
	}

	// Create Config
	config, err := okta.NewConfiguration(okta.WithOrgUrl(domain), okta.WithToken(apiToken))
	if err != nil {
		return nil, err
	}

	return config, nil
}
