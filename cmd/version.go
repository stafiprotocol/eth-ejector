package cmd

import (
	"encoding/json"
	"fmt"
	dbg "runtime/debug"

	"github.com/spf13/cobra"
)

var (
	Version string
	Commit  string
)

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "version",
		Aliases: []string{"v"},
		Args:    cobra.ExactArgs(0),
		Short:   "Show version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			bi, _ := dbg.ReadBuildInfo()

			dependencyVersions := map[string]string{}

			for _, dep := range bi.Deps {
				dependencyVersions[dep.Path] = dep.Version
			}

			v := version{
				Version:    Version,
				Commit:     Commit,
				GoEthereum: dependencyVersions["github.com/ethereum/go-ethereum"],
				Prysm:      dependencyVersions["github.com/prysmaticlabs/prysm/v3"],
			}

			bz, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(logo)
			fmt.Println(string(bz))
			return nil
		},
	}

	return cmd
}

type version struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	GoEthereum string `json:"go-ethereum"`
	Prysm      string `json:"prysm"`
}

var logo = `
             __                 ______   __ 
            /  |               /      \ /  |
  _______  _$$ |_     ______  /$$$$$$  |$$/ 
 /       |/ $$   |   /      \ $$ |_ $$/ /  |
/$$$$$$$/ $$$$$$/    $$$$$$  |$$   |    $$ |
$$      \   $$ | __  /    $$ |$$$$/     $$ |
 $$$$$$  |  $$ |/  |/$$$$$$$ |$$ |      $$ |
/     $$/   $$  $$/ $$    $$ |$$ |      $$ |
$$$$$$$/     $$$$/   $$$$$$$/ $$/       $$/ 
                                            
`
