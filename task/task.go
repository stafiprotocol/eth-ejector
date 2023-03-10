package task

import (
	"math"
	"math/big"
	"time"

	withdraw "eth-ejector/bindings/Withdraw"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v3/beacon-chain/core/signing"
	types "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v3/crypto/bls"
	"github.com/prysmaticlabs/prysm/v3/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
	prysmTime "github.com/prysmaticlabs/prysm/v3/time"
	"github.com/sirupsen/logrus"
	"github.com/stafiprotocol/eth2-balance-service/shared"
	"github.com/stafiprotocol/eth2-balance-service/shared/beacon"
	sharedTypes "github.com/stafiprotocol/eth2-balance-service/shared/types"
)

// testnet
var withdrawAddress = "0xc386e551c828e0b3f0A4AB2241e1e0F051f74496"

// mainnet
// var withdrawAddress = "0xc386e551c828e0b3f0A4AB2241e1e0F051f74496"

var domainVoluntaryExit = bytesutil.Uint32ToBytes4(0x04000000)
var shardCommitteePeriod = types.Epoch(256) // ShardCommitteePeriod is the minimum amount of epochs a validator must participate before exiting.

type Task struct {
	stop             chan struct{}
	validators       map[uint64]*Validator
	connection       *shared.Connection
	withdrawContract *withdraw.Withdraw
	eth2Config       *beacon.Eth2Config
}

type Validator struct {
	ValidatorIndex uint64
	Publickey      []byte
	PrivateKey     []byte
}

func NewTask(validators map[uint64]*Validator, connection *shared.Connection) *Task {
	s := &Task{
		stop:       make(chan struct{}),
		validators: validators,
		connection: connection,
	}
	return s
}

func (task *Task) Start() error {
	withdrawContract, err := withdraw.NewWithdraw(common.HexToAddress(withdrawAddress), task.connection.Eth1Client())
	if err != nil {
		return err
	}
	task.withdrawContract = withdrawContract

	ethConfig, err := task.connection.Eth2Client().GetEth2Config()
	if err != nil {
		return err
	}
	task.eth2Config = &ethConfig

	SafeGoWithRestart(task.monitorHandler)
	return nil
}

func (task *Task) Stop() {
	close(task.stop)
}

func (task *Task) monitorHandler() {
	logrus.Info("start monitor")

	for {
		select {
		case <-task.stop:
			logrus.Info("task has stopped")
			return
		default:
			startCycle, err := task.withdrawContract.EjectedStartCycle(task.connection.CallOpts(nil))
			if err != nil {
				logrus.Warnf("monitor err: %s", err)
				time.Sleep(6 * time.Second)
				continue
			}

			currentCycle, err := task.withdrawContract.CurrentWithdrawCycle(task.connection.CallOpts(nil))
			if err != nil {
				logrus.Warnf("monitor err: %s", err)
				time.Sleep(6 * time.Second)
				continue
			}

			start := startCycle.Int64()
			end := currentCycle.Int64()
			for i := start; i <= end; {
				err := task.checkCycle(i)
				if err != nil {
					logrus.Warnf("monitor check cycle: %d err: %s", i, err)
					time.Sleep(6 * time.Second)
					continue
				}
				i++
			}
		}

		break
	}

	for {
		select {
		case <-task.stop:
			logrus.Info("task has stopped")
			return
		default:

			logrus.Debug("checkCycle start -----------")
			currentCycle, err := task.withdrawContract.CurrentWithdrawCycle(task.connection.CallOpts(nil))
			if err != nil {
				logrus.Warnf("get currentWithdrawCycle err: %s", err)
				time.Sleep(6 * time.Second)
				continue
			}

			start := currentCycle.Int64() - 10
			end := currentCycle.Int64()

			for i := start; i <= end; i++ {
				err = task.checkCycle(i)
				if err != nil {
					logrus.Warnf("checkCycle %d err: %s", i, err)
					time.Sleep(6 * time.Second)
					continue
				}
			}
			logrus.Debug("checkCycle end -----------")
		}

		time.Sleep(15 * time.Second)
	}
}

func (task *Task) checkCycle(cycle int64) error {
	logrus.Debugf("checkCycle %d", cycle)
	ejectedValidators, err := task.withdrawContract.GetEjectedValidatorsAtCycle(task.connection.CallOpts(nil), big.NewInt(cycle))
	if err != nil {
		return err
	}

	for _, ejectedValidator := range ejectedValidators {
		if validator, exist := task.validators[ejectedValidator.Uint64()]; exist {
			logrus.Infof("validator %d elected at cycle %d", validator.ValidatorIndex, cycle)
			// check beacon sync status
			syncStatus, err := task.connection.Eth2Client().GetSyncStatus()
			if err != nil {
				return err
			}
			if syncStatus.Syncing {
				return errors.New("could not perform exit: beacon node is syncing.")
			}

			// check exited before
			pubkey := sharedTypes.BytesToValidatorPubkey(validator.Publickey)
			status, err := task.connection.GetValidatorStatus(pubkey, &beacon.ValidatorStatusOptions{})
			if err != nil {
				return err
			}
			// will skip if already sign exit
			if status.ExitEpoch != math.MaxUint64 {
				logrus.Infof("validator %d will exit at epoch %d", validator.ValidatorIndex, status.ExitEpoch)
				continue
			}

			// will sign and broadcast exit msg
			totalSecondsPassed := prysmTime.Now().Unix() - int64(task.eth2Config.GenesisTime)
			currentEpoch := types.Epoch(uint64(totalSecondsPassed) / uint64(task.eth2Config.SlotsPerEpoch*task.eth2Config.SecondsPerSlot))

			// not active
			if status.ActivationEpoch < uint64(currentEpoch) {
				logrus.Warnf("validator %d is not active and can't exit, will skip", validator.ValidatorIndex)
				continue
			}
			if currentEpoch < types.Epoch(status.ActivationEpoch)+shardCommitteePeriod {
				logrus.Warnf("validator %d is not active long enough and can't exit, will skip", validator.ValidatorIndex)
				continue
			}

			exit := &ethpb.VoluntaryExit{Epoch: currentEpoch, ValidatorIndex: types.ValidatorIndex(validator.ValidatorIndex)}

			domain, err := task.connection.Eth2Client().GetDomainData(domainVoluntaryExit[:], uint64(exit.Epoch))
			if err != nil {
				return errors.Wrap(err, "Get domainData failed")
			}
			exitRoot, err := signing.ComputeSigningRoot(exit, domain)
			if err != nil {
				return errors.Wrap(err, "ComputeSigningRoot failed")
			}

			secretKey, err := bls.SecretKeyFromBytes(validator.PrivateKey)
			if err != nil {
				return errors.Wrap(err, "failed to initialize keys caches from account keystore")
			}
			sig := secretKey.Sign(exitRoot[:])
			// signedExit := &ethpb.SignedVoluntaryExit{Exit: exit, Signature: sig.Marshal()}

			err = task.connection.Eth2Client().ExitValidator(validator.ValidatorIndex, uint64(currentEpoch), sharedTypes.BytesToValidatorSignature(sig.Marshal()))
			if err != nil {
				return err
			}

			logrus.Infof("validator %d broadcast voluntary exit ok", validator.ValidatorIndex)

		}
	}
	return nil
}
