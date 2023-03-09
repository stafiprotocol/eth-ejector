package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v3/crypto/bls"
	"github.com/prysmaticlabs/prysm/v3/io/file"
	"github.com/prysmaticlabs/prysm/v3/io/prompt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

const (
	flagKeysDir           = "keys_dir"
	flagExecutionEndpoint = "execution_endpoint"
	flagConsensusEndpoint = "consensus_endpoint"
	flagLogLevel          = "log_level"
)

// Keystore json file representation as a Go struct.
type Keystore struct {
	Crypto  map[string]interface{} `json:"crypto"`
	ID      string                 `json:"uuid"`
	Pubkey  string                 `json:"pubkey"`
	Version uint                   `json:"version"`
	Name    string                 `json:"name"`
	Path    string                 `json:"path"`
}

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "start",
		Aliases: []string{"s"},
		Args:    cobra.ExactArgs(0),
		Short:   "Start ejector process",
		RunE: func(cmd *cobra.Command, args []string) error {
			keysDir, err := cmd.Flags().GetString(flagKeysDir)
			if err != nil {
				return err
			}
			if len(keysDir) == 0 {
				return fmt.Errorf("%s empty", flagKeysDir)
			}
			executionEndpoint, err := cmd.Flags().GetString(flagExecutionEndpoint)
			if err != nil {
				return err
			}
			if len(executionEndpoint) == 0 {
				return fmt.Errorf("%s empty", flagExecutionEndpoint)
			}
			consensusEndpoint, err := cmd.Flags().GetString(flagConsensusEndpoint)
			if err != nil {
				return err
			}
			if len(consensusEndpoint) == 0 {
				return fmt.Errorf("%s empty", flagConsensusEndpoint)
			}
			logrus.Infof("%s: %s", flagKeysDir, keysDir)
			logrus.Infof("%s: %s", flagExecutionEndpoint, executionEndpoint)
			logrus.Infof("%s: %s", flagConsensusEndpoint, consensusEndpoint)

			keystores, err := parseKeysDir(keysDir)
			if err != nil {
				return errors.Wrap(err, "parseKeysDir failed")
			}

			for _, keystore := range keystores {
				logrus.Info("keystore", keystore)
			}

			accountsPassword, err := prompt.PasswordPrompt(
				"Enter the password for your imported accounts", prompt.NotEmpty,
			)
			if err != nil {
				return fmt.Errorf("could not read account password: %w", err)
			}
			logrus.Info("accountsPassword: ", accountsPassword)

			keys := map[string]string{}
			for _, keystore := range keystores {
				privKeyBytes, pubKeyBytes, _, err := attemptDecryptKeystore(keystore, accountsPassword)
				if err != nil {
					return err
				}
				// if key exists prior to being added then output log that duplicate key was found
				if _, ok := keys[string(pubKeyBytes)]; ok {
					logrus.Warnf("Duplicate key in import will be ignored: %#x", pubKeyBytes)
					continue
				}
				keys[string(pubKeyBytes)] = string(privKeyBytes)
				logrus.Info("pubkeyBtes: ", hex.EncodeToString(pubKeyBytes))
			}
			return nil
		},
	}

	cmd.Flags().String(flagKeysDir, "", "Path to a directory where keystores to be imported are stored (must provide)")
	cmd.Flags().String(flagExecutionEndpoint, "", "Execution node RPC provider endpoint (must provide)")
	cmd.Flags().String(flagConsensusEndpoint, "", "Consensue node RPC provider endpoint (must provide)")
	cmd.Flags().String(flagLogLevel, logrus.InfoLevel.String(), "The logging level (trace|debug|info|warn|error|fatal|panic)")
	return cmd
}

func parseKeysDir(keysDir string) ([]*Keystore, error) {

	isDir, err := file.HasDir(keysDir)
	if err != nil {
		return nil, errors.Wrap(err, "could not determine if path is a directory")
	}
	keystoresImported := make([]*Keystore, 0)
	if isDir {
		files, err := os.ReadDir(keysDir)
		if err != nil {
			return nil, errors.Wrap(err, "could not read dir")
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("directory %s has no files, cannot import from it", keysDir)
		}
		filesInDir := make([]string, 0)
		for i := 0; i < len(files); i++ {
			if files[i].IsDir() {
				continue
			}
			filesInDir = append(filesInDir, files[i].Name())
		}
		// Sort the imported keystores by derivation path if they
		// specify this value in their filename.
		sort.Sort(byDerivationPath(filesInDir))
		for _, name := range filesInDir {
			keystore, err := readKeystoreFile(filepath.Join(keysDir, name))
			if err != nil && strings.Contains(err.Error(), "could not decode keystore json") {
				continue
			} else if err != nil {
				return nil, errors.Wrapf(err, "could not import keystore at path: %s", name)
			}
			keystoresImported = append(keystoresImported, keystore)
		}
	} else {
		keystore, err := readKeystoreFile(keysDir)
		if err != nil {
			return nil, errors.Wrap(err, "could not import keystore")
		}
		keystoresImported = append(keystoresImported, keystore)
	}

	return keystoresImported, nil
}

var derivationPathRegex = regexp.MustCompile(`m_12381_3600_(\d+)_(\d+)_(\d+)`)

// byDerivationPath implements sort.Interface based on a
// derivation path present in a keystore filename, if any. This
// will allow us to sort filenames such as keystore-m_12381_3600_1_0_0.json
// in a directory and import them nicely in order of the derivation path.
type byDerivationPath []string

// Len is the number of elements in the collection.
func (fileNames byDerivationPath) Len() int { return len(fileNames) }

// Less reports whether the element with index i must sort before the element with index j.
func (fileNames byDerivationPath) Less(i, j int) bool {
	// We check if file name at index i has a derivation path
	// in the filename. If it does not, then it is not less than j, and
	// we should swap it towards the end of the sorted list.
	if !derivationPathRegex.MatchString(fileNames[i]) {
		return false
	}
	derivationPathA := derivationPathRegex.FindString(fileNames[i])
	derivationPathB := derivationPathRegex.FindString(fileNames[j])
	if derivationPathA == "" {
		return false
	}
	if derivationPathB == "" {
		return true
	}
	a, err := strconv.Atoi(accountIndexFromFileName(derivationPathA))
	if err != nil {
		return false
	}
	b, err := strconv.Atoi(accountIndexFromFileName(derivationPathB))
	if err != nil {
		return false
	}
	return a < b
}

// Swap swaps the elements with indexes i and j.
func (fileNames byDerivationPath) Swap(i, j int) {
	fileNames[i], fileNames[j] = fileNames[j], fileNames[i]
}

func readKeystoreFile(keystoreFilePath string) (*Keystore, error) {
	keystoreBytes, err := os.ReadFile(keystoreFilePath) // #nosec G304
	if err != nil {
		return nil, errors.Wrap(err, "could not read keystore file")
	}
	keystoreFile := &Keystore{}
	if err := json.Unmarshal(keystoreBytes, keystoreFile); err != nil {
		return nil, errors.Wrap(err, "could not decode keystore json")
	}
	if keystoreFile.Pubkey == "" {
		return nil, errors.New("could not decode keystore json")
	}
	return keystoreFile, nil
}

// Extracts the account index, j, from a derivation path in a file name
// with the format m_12381_3600_j_0_0.
func accountIndexFromFileName(derivationPath string) string {
	derivationPath = derivationPath[13:]
	accIndexEnd := strings.Index(derivationPath, "_")
	return derivationPath[:accIndexEnd]
}

const IncorrectPasswordErrMsg = "invalid checksum"

// Retrieves the private key and public key from an EIP-2335 keystore file
// by decrypting using a specified password. If the password fails,
// it prompts the user for the correct password until it confirms.
func attemptDecryptKeystore(keystore *Keystore, password string,
) ([]byte, []byte, string, error) {
	enc := keystorev4.New()
	// Attempt to decrypt the keystore with the specifies password.
	var privKeyBytes []byte
	var err error
	privKeyBytes, err = enc.Decrypt(keystore.Crypto, password)
	doesNotDecrypt := err != nil && strings.Contains(err.Error(), IncorrectPasswordErrMsg)
	if doesNotDecrypt {
		return nil, nil, "", fmt.Errorf(
			"incorrect password for key 0x%s",
			keystore.Pubkey,
		)
	}
	if err != nil && !strings.Contains(err.Error(), IncorrectPasswordErrMsg) {
		return nil, nil, "", errors.Wrap(err, "could not decrypt keystore")
	}
	var pubKeyBytes []byte
	// Attempt to use the pubkey present in the keystore itself as a field. If unavailable,
	// then utilize the public key directly from the private key.
	if keystore.Pubkey != "" {
		pubKeyBytes, err = hex.DecodeString(keystore.Pubkey)
		if err != nil {
			return nil, nil, "", errors.Wrap(err, "could not decode pubkey from keystore")
		}
	} else {
		privKey, err := bls.SecretKeyFromBytes(privKeyBytes)
		if err != nil {
			return nil, nil, "", errors.Wrap(err, "could not initialize private key from bytes")
		}
		pubKeyBytes = privKey.PublicKey().Marshal()
	}
	return privKeyBytes, pubKeyBytes, password, nil
}
