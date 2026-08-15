package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// Sentinel errors to prevent dynamic error generation (err113).
var (
	ErrUnsupportedShell = errors.New("unsupported shell")
)

// NewCompletionCmd creates and returns the completion command for shell autocompletion.
// This factory pattern prevents global state pollution.
func NewCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for Hako.

To load completions:

Bash:
  $ source <(hako completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ hako completion bash > /etc/bash_completion.d/hako
  # macOS:
  $ hako completion bash > /usr/local/etc/bash_completion.d/hako

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ hako completion zsh > "${fpath[1]}/_hako"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ hako completion fish | source

  # To load completions for each session, execute once:
  $ hako completion fish > ~/.config/fish/completions/hako.fish

PowerShell:
  PS> hako completion powershell | Out-String | Invoke-Expression

  # To load completions for each session, execute once:
  PS> hako completion powershell > hako.ps1
  PS> . .\hako.ps1
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE:                  runCompletion,
	}

	return cmd
}

func runCompletion(cmd *cobra.Command, args []string) error {
	shell := args[0]

	switch shell {
	case "bash":
		return cmd.Root().GenBashCompletion(cmd.OutOrStdout())
	case "zsh":
		return cmd.Root().GenZshCompletion(cmd.OutOrStdout())
	case "fish":
		return cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
	case "powershell":
		return cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedShell, shell)
	}
}
