// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package withdraw

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// WithdrawMetaData contains all meta data concerning the Withdraw contract.
var WithdrawMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"time\",\"type\":\"uint256\"}],\"name\":\"EtherDeposited\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"withdrawCycle\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"ejectedStartWithdrawCycle\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256[]\",\"name\":\"ejectedValidators\",\"type\":\"uint256[]\"}],\"name\":\"NotifyValidatorExit\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"proposalId\",\"type\":\"bytes32\"}],\"name\":\"ProposalExecuted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"rethAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"ethAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"withdrawIndex\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"instantly\",\"type\":\"bool\"}],\"name\":\"Unstake\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"proposalId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"voter\",\"type\":\"address\"}],\"name\":\"VoteProposal\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256[]\",\"name\":\"withdrawIndexList\",\"type\":\"uint256[]\"}],\"name\":\"Withdraw\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"currentWithdrawCycle\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"depositEth\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_dealedHeight\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_userAmount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_nodeAmount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_platformAmount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_maxClaimableWithdrawIndex\",\"type\":\"uint256\"}],\"name\":\"distributeWithdrawals\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"ejectedStartCycle\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"ejectedValidatorsAtCycle\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"cycle\",\"type\":\"uint256\"}],\"name\":\"getEjectedValidatorsAtCycle\",\"outputs\":[{\"internalType\":\"uint256[]\",\"name\":\"\",\"type\":\"uint256[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"}],\"name\":\"getUnclaimedWithdrawalsOfUser\",\"outputs\":[{\"internalType\":\"uint256[]\",\"name\":\"\",\"type\":\"uint256[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_stafiStorageAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_withdrawLimitPerCycle\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_userWithdrawLimitPerCycle\",\"type\":\"uint256\"}],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"latestDistributeHeight\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"maxClaimableWithdrawIndex\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"nextWithdrawIndex\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_withdrawCycle\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_ejectedStartCycle\",\"type\":\"uint256\"},{\"internalType\":\"uint256[]\",\"name\":\"_validatorIndexList\",\"type\":\"uint256[]\"}],\"name\":\"notifyValidatorExit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_withdrawCycle\",\"type\":\"uint256\"}],\"name\":\"reserveEthForWithdraw\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_userWithdrawLimitPerCycle\",\"type\":\"uint256\"}],\"name\":\"setUserWithdrawLimitPerCycle\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_withdrawLimitPerCycle\",\"type\":\"uint256\"}],\"name\":\"setWithdrawLimitPerCycle\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalMissingAmountForWithdraw\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"totalWithdrawAmountAtCycle\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_rEthAmount\",\"type\":\"uint256\"}],\"name\":\"unstake\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"userWithdrawAmountAtCycle\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"userWithdrawLimitPerCycle\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256[]\",\"name\":\"_withdrawIndexList\",\"type\":\"uint256[]\"}],\"name\":\"withdraw\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"withdrawLimitPerCycle\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"withdrawalAtIndex\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"_address\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_amount\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"stateMutability\":\"payable\",\"type\":\"receive\"}]",
}

// WithdrawABI is the input ABI used to generate the binding from.
// Deprecated: Use WithdrawMetaData.ABI instead.
var WithdrawABI = WithdrawMetaData.ABI

// Withdraw is an auto generated Go binding around an Ethereum contract.
type Withdraw struct {
	WithdrawCaller     // Read-only binding to the contract
	WithdrawTransactor // Write-only binding to the contract
	WithdrawFilterer   // Log filterer for contract events
}

// WithdrawCaller is an auto generated read-only Go binding around an Ethereum contract.
type WithdrawCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WithdrawTransactor is an auto generated write-only Go binding around an Ethereum contract.
type WithdrawTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WithdrawFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type WithdrawFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WithdrawSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type WithdrawSession struct {
	Contract     *Withdraw         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// WithdrawCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type WithdrawCallerSession struct {
	Contract *WithdrawCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// WithdrawTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type WithdrawTransactorSession struct {
	Contract     *WithdrawTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// WithdrawRaw is an auto generated low-level Go binding around an Ethereum contract.
type WithdrawRaw struct {
	Contract *Withdraw // Generic contract binding to access the raw methods on
}

// WithdrawCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type WithdrawCallerRaw struct {
	Contract *WithdrawCaller // Generic read-only contract binding to access the raw methods on
}

// WithdrawTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type WithdrawTransactorRaw struct {
	Contract *WithdrawTransactor // Generic write-only contract binding to access the raw methods on
}

// NewWithdraw creates a new instance of Withdraw, bound to a specific deployed contract.
func NewWithdraw(address common.Address, backend bind.ContractBackend) (*Withdraw, error) {
	contract, err := bindWithdraw(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Withdraw{WithdrawCaller: WithdrawCaller{contract: contract}, WithdrawTransactor: WithdrawTransactor{contract: contract}, WithdrawFilterer: WithdrawFilterer{contract: contract}}, nil
}

// NewWithdrawCaller creates a new read-only instance of Withdraw, bound to a specific deployed contract.
func NewWithdrawCaller(address common.Address, caller bind.ContractCaller) (*WithdrawCaller, error) {
	contract, err := bindWithdraw(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &WithdrawCaller{contract: contract}, nil
}

// NewWithdrawTransactor creates a new write-only instance of Withdraw, bound to a specific deployed contract.
func NewWithdrawTransactor(address common.Address, transactor bind.ContractTransactor) (*WithdrawTransactor, error) {
	contract, err := bindWithdraw(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &WithdrawTransactor{contract: contract}, nil
}

// NewWithdrawFilterer creates a new log filterer instance of Withdraw, bound to a specific deployed contract.
func NewWithdrawFilterer(address common.Address, filterer bind.ContractFilterer) (*WithdrawFilterer, error) {
	contract, err := bindWithdraw(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &WithdrawFilterer{contract: contract}, nil
}

// bindWithdraw binds a generic wrapper to an already deployed contract.
func bindWithdraw(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(WithdrawABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Withdraw *WithdrawRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Withdraw.Contract.WithdrawCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Withdraw *WithdrawRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Withdraw.Contract.WithdrawTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Withdraw *WithdrawRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Withdraw.Contract.WithdrawTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Withdraw *WithdrawCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Withdraw.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Withdraw *WithdrawTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Withdraw.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Withdraw *WithdrawTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Withdraw.Contract.contract.Transact(opts, method, params...)
}

// CurrentWithdrawCycle is a free data retrieval call binding the contract method 0xdb17815b.
//
// Solidity: function currentWithdrawCycle() view returns(uint256)
func (_Withdraw *WithdrawCaller) CurrentWithdrawCycle(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "currentWithdrawCycle")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// CurrentWithdrawCycle is a free data retrieval call binding the contract method 0xdb17815b.
//
// Solidity: function currentWithdrawCycle() view returns(uint256)
func (_Withdraw *WithdrawSession) CurrentWithdrawCycle() (*big.Int, error) {
	return _Withdraw.Contract.CurrentWithdrawCycle(&_Withdraw.CallOpts)
}

// CurrentWithdrawCycle is a free data retrieval call binding the contract method 0xdb17815b.
//
// Solidity: function currentWithdrawCycle() view returns(uint256)
func (_Withdraw *WithdrawCallerSession) CurrentWithdrawCycle() (*big.Int, error) {
	return _Withdraw.Contract.CurrentWithdrawCycle(&_Withdraw.CallOpts)
}

// EjectedStartCycle is a free data retrieval call binding the contract method 0x8a699828.
//
// Solidity: function ejectedStartCycle() view returns(uint256)
func (_Withdraw *WithdrawCaller) EjectedStartCycle(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "ejectedStartCycle")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// EjectedStartCycle is a free data retrieval call binding the contract method 0x8a699828.
//
// Solidity: function ejectedStartCycle() view returns(uint256)
func (_Withdraw *WithdrawSession) EjectedStartCycle() (*big.Int, error) {
	return _Withdraw.Contract.EjectedStartCycle(&_Withdraw.CallOpts)
}

// EjectedStartCycle is a free data retrieval call binding the contract method 0x8a699828.
//
// Solidity: function ejectedStartCycle() view returns(uint256)
func (_Withdraw *WithdrawCallerSession) EjectedStartCycle() (*big.Int, error) {
	return _Withdraw.Contract.EjectedStartCycle(&_Withdraw.CallOpts)
}

// EjectedValidatorsAtCycle is a free data retrieval call binding the contract method 0x261a792d.
//
// Solidity: function ejectedValidatorsAtCycle(uint256 , uint256 ) view returns(uint256)
func (_Withdraw *WithdrawCaller) EjectedValidatorsAtCycle(opts *bind.CallOpts, arg0 *big.Int, arg1 *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "ejectedValidatorsAtCycle", arg0, arg1)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// EjectedValidatorsAtCycle is a free data retrieval call binding the contract method 0x261a792d.
//
// Solidity: function ejectedValidatorsAtCycle(uint256 , uint256 ) view returns(uint256)
func (_Withdraw *WithdrawSession) EjectedValidatorsAtCycle(arg0 *big.Int, arg1 *big.Int) (*big.Int, error) {
	return _Withdraw.Contract.EjectedValidatorsAtCycle(&_Withdraw.CallOpts, arg0, arg1)
}

// EjectedValidatorsAtCycle is a free data retrieval call binding the contract method 0x261a792d.
//
// Solidity: function ejectedValidatorsAtCycle(uint256 , uint256 ) view returns(uint256)
func (_Withdraw *WithdrawCallerSession) EjectedValidatorsAtCycle(arg0 *big.Int, arg1 *big.Int) (*big.Int, error) {
	return _Withdraw.Contract.EjectedValidatorsAtCycle(&_Withdraw.CallOpts, arg0, arg1)
}

// GetEjectedValidatorsAtCycle is a free data retrieval call binding the contract method 0x2c0f4166.
//
// Solidity: function getEjectedValidatorsAtCycle(uint256 cycle) view returns(uint256[])
func (_Withdraw *WithdrawCaller) GetEjectedValidatorsAtCycle(opts *bind.CallOpts, cycle *big.Int) ([]*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "getEjectedValidatorsAtCycle", cycle)

	if err != nil {
		return *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new([]*big.Int)).(*[]*big.Int)

	return out0, err

}

// GetEjectedValidatorsAtCycle is a free data retrieval call binding the contract method 0x2c0f4166.
//
// Solidity: function getEjectedValidatorsAtCycle(uint256 cycle) view returns(uint256[])
func (_Withdraw *WithdrawSession) GetEjectedValidatorsAtCycle(cycle *big.Int) ([]*big.Int, error) {
	return _Withdraw.Contract.GetEjectedValidatorsAtCycle(&_Withdraw.CallOpts, cycle)
}

// GetEjectedValidatorsAtCycle is a free data retrieval call binding the contract method 0x2c0f4166.
//
// Solidity: function getEjectedValidatorsAtCycle(uint256 cycle) view returns(uint256[])
func (_Withdraw *WithdrawCallerSession) GetEjectedValidatorsAtCycle(cycle *big.Int) ([]*big.Int, error) {
	return _Withdraw.Contract.GetEjectedValidatorsAtCycle(&_Withdraw.CallOpts, cycle)
}

// GetUnclaimedWithdrawalsOfUser is a free data retrieval call binding the contract method 0xfd6b5a49.
//
// Solidity: function getUnclaimedWithdrawalsOfUser(address user) view returns(uint256[])
func (_Withdraw *WithdrawCaller) GetUnclaimedWithdrawalsOfUser(opts *bind.CallOpts, user common.Address) ([]*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "getUnclaimedWithdrawalsOfUser", user)

	if err != nil {
		return *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new([]*big.Int)).(*[]*big.Int)

	return out0, err

}

// GetUnclaimedWithdrawalsOfUser is a free data retrieval call binding the contract method 0xfd6b5a49.
//
// Solidity: function getUnclaimedWithdrawalsOfUser(address user) view returns(uint256[])
func (_Withdraw *WithdrawSession) GetUnclaimedWithdrawalsOfUser(user common.Address) ([]*big.Int, error) {
	return _Withdraw.Contract.GetUnclaimedWithdrawalsOfUser(&_Withdraw.CallOpts, user)
}

// GetUnclaimedWithdrawalsOfUser is a free data retrieval call binding the contract method 0xfd6b5a49.
//
// Solidity: function getUnclaimedWithdrawalsOfUser(address user) view returns(uint256[])
func (_Withdraw *WithdrawCallerSession) GetUnclaimedWithdrawalsOfUser(user common.Address) ([]*big.Int, error) {
	return _Withdraw.Contract.GetUnclaimedWithdrawalsOfUser(&_Withdraw.CallOpts, user)
}

// LatestDistributeHeight is a free data retrieval call binding the contract method 0x69a2b804.
//
// Solidity: function latestDistributeHeight() view returns(uint256)
func (_Withdraw *WithdrawCaller) LatestDistributeHeight(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "latestDistributeHeight")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// LatestDistributeHeight is a free data retrieval call binding the contract method 0x69a2b804.
//
// Solidity: function latestDistributeHeight() view returns(uint256)
func (_Withdraw *WithdrawSession) LatestDistributeHeight() (*big.Int, error) {
	return _Withdraw.Contract.LatestDistributeHeight(&_Withdraw.CallOpts)
}

// LatestDistributeHeight is a free data retrieval call binding the contract method 0x69a2b804.
//
// Solidity: function latestDistributeHeight() view returns(uint256)
func (_Withdraw *WithdrawCallerSession) LatestDistributeHeight() (*big.Int, error) {
	return _Withdraw.Contract.LatestDistributeHeight(&_Withdraw.CallOpts)
}

// MaxClaimableWithdrawIndex is a free data retrieval call binding the contract method 0x0a64041b.
//
// Solidity: function maxClaimableWithdrawIndex() view returns(uint256)
func (_Withdraw *WithdrawCaller) MaxClaimableWithdrawIndex(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "maxClaimableWithdrawIndex")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// MaxClaimableWithdrawIndex is a free data retrieval call binding the contract method 0x0a64041b.
//
// Solidity: function maxClaimableWithdrawIndex() view returns(uint256)
func (_Withdraw *WithdrawSession) MaxClaimableWithdrawIndex() (*big.Int, error) {
	return _Withdraw.Contract.MaxClaimableWithdrawIndex(&_Withdraw.CallOpts)
}

// MaxClaimableWithdrawIndex is a free data retrieval call binding the contract method 0x0a64041b.
//
// Solidity: function maxClaimableWithdrawIndex() view returns(uint256)
func (_Withdraw *WithdrawCallerSession) MaxClaimableWithdrawIndex() (*big.Int, error) {
	return _Withdraw.Contract.MaxClaimableWithdrawIndex(&_Withdraw.CallOpts)
}

// NextWithdrawIndex is a free data retrieval call binding the contract method 0x7e4dc15c.
//
// Solidity: function nextWithdrawIndex() view returns(uint256)
func (_Withdraw *WithdrawCaller) NextWithdrawIndex(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "nextWithdrawIndex")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// NextWithdrawIndex is a free data retrieval call binding the contract method 0x7e4dc15c.
//
// Solidity: function nextWithdrawIndex() view returns(uint256)
func (_Withdraw *WithdrawSession) NextWithdrawIndex() (*big.Int, error) {
	return _Withdraw.Contract.NextWithdrawIndex(&_Withdraw.CallOpts)
}

// NextWithdrawIndex is a free data retrieval call binding the contract method 0x7e4dc15c.
//
// Solidity: function nextWithdrawIndex() view returns(uint256)
func (_Withdraw *WithdrawCallerSession) NextWithdrawIndex() (*big.Int, error) {
	return _Withdraw.Contract.NextWithdrawIndex(&_Withdraw.CallOpts)
}

// TotalMissingAmountForWithdraw is a free data retrieval call binding the contract method 0x3c677dbe.
//
// Solidity: function totalMissingAmountForWithdraw() view returns(uint256)
func (_Withdraw *WithdrawCaller) TotalMissingAmountForWithdraw(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "totalMissingAmountForWithdraw")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalMissingAmountForWithdraw is a free data retrieval call binding the contract method 0x3c677dbe.
//
// Solidity: function totalMissingAmountForWithdraw() view returns(uint256)
func (_Withdraw *WithdrawSession) TotalMissingAmountForWithdraw() (*big.Int, error) {
	return _Withdraw.Contract.TotalMissingAmountForWithdraw(&_Withdraw.CallOpts)
}

// TotalMissingAmountForWithdraw is a free data retrieval call binding the contract method 0x3c677dbe.
//
// Solidity: function totalMissingAmountForWithdraw() view returns(uint256)
func (_Withdraw *WithdrawCallerSession) TotalMissingAmountForWithdraw() (*big.Int, error) {
	return _Withdraw.Contract.TotalMissingAmountForWithdraw(&_Withdraw.CallOpts)
}

// TotalWithdrawAmountAtCycle is a free data retrieval call binding the contract method 0x8a726d78.
//
// Solidity: function totalWithdrawAmountAtCycle(uint256 ) view returns(uint256)
func (_Withdraw *WithdrawCaller) TotalWithdrawAmountAtCycle(opts *bind.CallOpts, arg0 *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "totalWithdrawAmountAtCycle", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalWithdrawAmountAtCycle is a free data retrieval call binding the contract method 0x8a726d78.
//
// Solidity: function totalWithdrawAmountAtCycle(uint256 ) view returns(uint256)
func (_Withdraw *WithdrawSession) TotalWithdrawAmountAtCycle(arg0 *big.Int) (*big.Int, error) {
	return _Withdraw.Contract.TotalWithdrawAmountAtCycle(&_Withdraw.CallOpts, arg0)
}

// TotalWithdrawAmountAtCycle is a free data retrieval call binding the contract method 0x8a726d78.
//
// Solidity: function totalWithdrawAmountAtCycle(uint256 ) view returns(uint256)
func (_Withdraw *WithdrawCallerSession) TotalWithdrawAmountAtCycle(arg0 *big.Int) (*big.Int, error) {
	return _Withdraw.Contract.TotalWithdrawAmountAtCycle(&_Withdraw.CallOpts, arg0)
}

// UserWithdrawAmountAtCycle is a free data retrieval call binding the contract method 0xf5ff612d.
//
// Solidity: function userWithdrawAmountAtCycle(address , uint256 ) view returns(uint256)
func (_Withdraw *WithdrawCaller) UserWithdrawAmountAtCycle(opts *bind.CallOpts, arg0 common.Address, arg1 *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "userWithdrawAmountAtCycle", arg0, arg1)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// UserWithdrawAmountAtCycle is a free data retrieval call binding the contract method 0xf5ff612d.
//
// Solidity: function userWithdrawAmountAtCycle(address , uint256 ) view returns(uint256)
func (_Withdraw *WithdrawSession) UserWithdrawAmountAtCycle(arg0 common.Address, arg1 *big.Int) (*big.Int, error) {
	return _Withdraw.Contract.UserWithdrawAmountAtCycle(&_Withdraw.CallOpts, arg0, arg1)
}

// UserWithdrawAmountAtCycle is a free data retrieval call binding the contract method 0xf5ff612d.
//
// Solidity: function userWithdrawAmountAtCycle(address , uint256 ) view returns(uint256)
func (_Withdraw *WithdrawCallerSession) UserWithdrawAmountAtCycle(arg0 common.Address, arg1 *big.Int) (*big.Int, error) {
	return _Withdraw.Contract.UserWithdrawAmountAtCycle(&_Withdraw.CallOpts, arg0, arg1)
}

// UserWithdrawLimitPerCycle is a free data retrieval call binding the contract method 0x86390fc7.
//
// Solidity: function userWithdrawLimitPerCycle() view returns(uint256)
func (_Withdraw *WithdrawCaller) UserWithdrawLimitPerCycle(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "userWithdrawLimitPerCycle")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// UserWithdrawLimitPerCycle is a free data retrieval call binding the contract method 0x86390fc7.
//
// Solidity: function userWithdrawLimitPerCycle() view returns(uint256)
func (_Withdraw *WithdrawSession) UserWithdrawLimitPerCycle() (*big.Int, error) {
	return _Withdraw.Contract.UserWithdrawLimitPerCycle(&_Withdraw.CallOpts)
}

// UserWithdrawLimitPerCycle is a free data retrieval call binding the contract method 0x86390fc7.
//
// Solidity: function userWithdrawLimitPerCycle() view returns(uint256)
func (_Withdraw *WithdrawCallerSession) UserWithdrawLimitPerCycle() (*big.Int, error) {
	return _Withdraw.Contract.UserWithdrawLimitPerCycle(&_Withdraw.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(uint8)
func (_Withdraw *WithdrawCaller) Version(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(uint8)
func (_Withdraw *WithdrawSession) Version() (uint8, error) {
	return _Withdraw.Contract.Version(&_Withdraw.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(uint8)
func (_Withdraw *WithdrawCallerSession) Version() (uint8, error) {
	return _Withdraw.Contract.Version(&_Withdraw.CallOpts)
}

// WithdrawLimitPerCycle is a free data retrieval call binding the contract method 0x406bb26f.
//
// Solidity: function withdrawLimitPerCycle() view returns(uint256)
func (_Withdraw *WithdrawCaller) WithdrawLimitPerCycle(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "withdrawLimitPerCycle")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// WithdrawLimitPerCycle is a free data retrieval call binding the contract method 0x406bb26f.
//
// Solidity: function withdrawLimitPerCycle() view returns(uint256)
func (_Withdraw *WithdrawSession) WithdrawLimitPerCycle() (*big.Int, error) {
	return _Withdraw.Contract.WithdrawLimitPerCycle(&_Withdraw.CallOpts)
}

// WithdrawLimitPerCycle is a free data retrieval call binding the contract method 0x406bb26f.
//
// Solidity: function withdrawLimitPerCycle() view returns(uint256)
func (_Withdraw *WithdrawCallerSession) WithdrawLimitPerCycle() (*big.Int, error) {
	return _Withdraw.Contract.WithdrawLimitPerCycle(&_Withdraw.CallOpts)
}

// WithdrawalAtIndex is a free data retrieval call binding the contract method 0xa8e1b8ef.
//
// Solidity: function withdrawalAtIndex(uint256 ) view returns(address _address, uint256 _amount)
func (_Withdraw *WithdrawCaller) WithdrawalAtIndex(opts *bind.CallOpts, arg0 *big.Int) (struct {
	Address common.Address
	Amount  *big.Int
}, error) {
	var out []interface{}
	err := _Withdraw.contract.Call(opts, &out, "withdrawalAtIndex", arg0)

	outstruct := new(struct {
		Address common.Address
		Amount  *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Address = *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	outstruct.Amount = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// WithdrawalAtIndex is a free data retrieval call binding the contract method 0xa8e1b8ef.
//
// Solidity: function withdrawalAtIndex(uint256 ) view returns(address _address, uint256 _amount)
func (_Withdraw *WithdrawSession) WithdrawalAtIndex(arg0 *big.Int) (struct {
	Address common.Address
	Amount  *big.Int
}, error) {
	return _Withdraw.Contract.WithdrawalAtIndex(&_Withdraw.CallOpts, arg0)
}

// WithdrawalAtIndex is a free data retrieval call binding the contract method 0xa8e1b8ef.
//
// Solidity: function withdrawalAtIndex(uint256 ) view returns(address _address, uint256 _amount)
func (_Withdraw *WithdrawCallerSession) WithdrawalAtIndex(arg0 *big.Int) (struct {
	Address common.Address
	Amount  *big.Int
}, error) {
	return _Withdraw.Contract.WithdrawalAtIndex(&_Withdraw.CallOpts, arg0)
}

// DepositEth is a paid mutator transaction binding the contract method 0x439370b1.
//
// Solidity: function depositEth() payable returns()
func (_Withdraw *WithdrawTransactor) DepositEth(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "depositEth")
}

// DepositEth is a paid mutator transaction binding the contract method 0x439370b1.
//
// Solidity: function depositEth() payable returns()
func (_Withdraw *WithdrawSession) DepositEth() (*types.Transaction, error) {
	return _Withdraw.Contract.DepositEth(&_Withdraw.TransactOpts)
}

// DepositEth is a paid mutator transaction binding the contract method 0x439370b1.
//
// Solidity: function depositEth() payable returns()
func (_Withdraw *WithdrawTransactorSession) DepositEth() (*types.Transaction, error) {
	return _Withdraw.Contract.DepositEth(&_Withdraw.TransactOpts)
}

// DistributeWithdrawals is a paid mutator transaction binding the contract method 0xb3971334.
//
// Solidity: function distributeWithdrawals(uint256 _dealedHeight, uint256 _userAmount, uint256 _nodeAmount, uint256 _platformAmount, uint256 _maxClaimableWithdrawIndex) returns()
func (_Withdraw *WithdrawTransactor) DistributeWithdrawals(opts *bind.TransactOpts, _dealedHeight *big.Int, _userAmount *big.Int, _nodeAmount *big.Int, _platformAmount *big.Int, _maxClaimableWithdrawIndex *big.Int) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "distributeWithdrawals", _dealedHeight, _userAmount, _nodeAmount, _platformAmount, _maxClaimableWithdrawIndex)
}

// DistributeWithdrawals is a paid mutator transaction binding the contract method 0xb3971334.
//
// Solidity: function distributeWithdrawals(uint256 _dealedHeight, uint256 _userAmount, uint256 _nodeAmount, uint256 _platformAmount, uint256 _maxClaimableWithdrawIndex) returns()
func (_Withdraw *WithdrawSession) DistributeWithdrawals(_dealedHeight *big.Int, _userAmount *big.Int, _nodeAmount *big.Int, _platformAmount *big.Int, _maxClaimableWithdrawIndex *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.DistributeWithdrawals(&_Withdraw.TransactOpts, _dealedHeight, _userAmount, _nodeAmount, _platformAmount, _maxClaimableWithdrawIndex)
}

// DistributeWithdrawals is a paid mutator transaction binding the contract method 0xb3971334.
//
// Solidity: function distributeWithdrawals(uint256 _dealedHeight, uint256 _userAmount, uint256 _nodeAmount, uint256 _platformAmount, uint256 _maxClaimableWithdrawIndex) returns()
func (_Withdraw *WithdrawTransactorSession) DistributeWithdrawals(_dealedHeight *big.Int, _userAmount *big.Int, _nodeAmount *big.Int, _platformAmount *big.Int, _maxClaimableWithdrawIndex *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.DistributeWithdrawals(&_Withdraw.TransactOpts, _dealedHeight, _userAmount, _nodeAmount, _platformAmount, _maxClaimableWithdrawIndex)
}

// Initialize is a paid mutator transaction binding the contract method 0x7a1ac61e.
//
// Solidity: function initialize(address _stafiStorageAddress, uint256 _withdrawLimitPerCycle, uint256 _userWithdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawTransactor) Initialize(opts *bind.TransactOpts, _stafiStorageAddress common.Address, _withdrawLimitPerCycle *big.Int, _userWithdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "initialize", _stafiStorageAddress, _withdrawLimitPerCycle, _userWithdrawLimitPerCycle)
}

// Initialize is a paid mutator transaction binding the contract method 0x7a1ac61e.
//
// Solidity: function initialize(address _stafiStorageAddress, uint256 _withdrawLimitPerCycle, uint256 _userWithdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawSession) Initialize(_stafiStorageAddress common.Address, _withdrawLimitPerCycle *big.Int, _userWithdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.Initialize(&_Withdraw.TransactOpts, _stafiStorageAddress, _withdrawLimitPerCycle, _userWithdrawLimitPerCycle)
}

// Initialize is a paid mutator transaction binding the contract method 0x7a1ac61e.
//
// Solidity: function initialize(address _stafiStorageAddress, uint256 _withdrawLimitPerCycle, uint256 _userWithdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawTransactorSession) Initialize(_stafiStorageAddress common.Address, _withdrawLimitPerCycle *big.Int, _userWithdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.Initialize(&_Withdraw.TransactOpts, _stafiStorageAddress, _withdrawLimitPerCycle, _userWithdrawLimitPerCycle)
}

// NotifyValidatorExit is a paid mutator transaction binding the contract method 0x1e0f4aae.
//
// Solidity: function notifyValidatorExit(uint256 _withdrawCycle, uint256 _ejectedStartCycle, uint256[] _validatorIndexList) returns()
func (_Withdraw *WithdrawTransactor) NotifyValidatorExit(opts *bind.TransactOpts, _withdrawCycle *big.Int, _ejectedStartCycle *big.Int, _validatorIndexList []*big.Int) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "notifyValidatorExit", _withdrawCycle, _ejectedStartCycle, _validatorIndexList)
}

// NotifyValidatorExit is a paid mutator transaction binding the contract method 0x1e0f4aae.
//
// Solidity: function notifyValidatorExit(uint256 _withdrawCycle, uint256 _ejectedStartCycle, uint256[] _validatorIndexList) returns()
func (_Withdraw *WithdrawSession) NotifyValidatorExit(_withdrawCycle *big.Int, _ejectedStartCycle *big.Int, _validatorIndexList []*big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.NotifyValidatorExit(&_Withdraw.TransactOpts, _withdrawCycle, _ejectedStartCycle, _validatorIndexList)
}

// NotifyValidatorExit is a paid mutator transaction binding the contract method 0x1e0f4aae.
//
// Solidity: function notifyValidatorExit(uint256 _withdrawCycle, uint256 _ejectedStartCycle, uint256[] _validatorIndexList) returns()
func (_Withdraw *WithdrawTransactorSession) NotifyValidatorExit(_withdrawCycle *big.Int, _ejectedStartCycle *big.Int, _validatorIndexList []*big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.NotifyValidatorExit(&_Withdraw.TransactOpts, _withdrawCycle, _ejectedStartCycle, _validatorIndexList)
}

// ReserveEthForWithdraw is a paid mutator transaction binding the contract method 0xeb1e88d3.
//
// Solidity: function reserveEthForWithdraw(uint256 _withdrawCycle) returns()
func (_Withdraw *WithdrawTransactor) ReserveEthForWithdraw(opts *bind.TransactOpts, _withdrawCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "reserveEthForWithdraw", _withdrawCycle)
}

// ReserveEthForWithdraw is a paid mutator transaction binding the contract method 0xeb1e88d3.
//
// Solidity: function reserveEthForWithdraw(uint256 _withdrawCycle) returns()
func (_Withdraw *WithdrawSession) ReserveEthForWithdraw(_withdrawCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.ReserveEthForWithdraw(&_Withdraw.TransactOpts, _withdrawCycle)
}

// ReserveEthForWithdraw is a paid mutator transaction binding the contract method 0xeb1e88d3.
//
// Solidity: function reserveEthForWithdraw(uint256 _withdrawCycle) returns()
func (_Withdraw *WithdrawTransactorSession) ReserveEthForWithdraw(_withdrawCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.ReserveEthForWithdraw(&_Withdraw.TransactOpts, _withdrawCycle)
}

// SetUserWithdrawLimitPerCycle is a paid mutator transaction binding the contract method 0x0e8f3292.
//
// Solidity: function setUserWithdrawLimitPerCycle(uint256 _userWithdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawTransactor) SetUserWithdrawLimitPerCycle(opts *bind.TransactOpts, _userWithdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "setUserWithdrawLimitPerCycle", _userWithdrawLimitPerCycle)
}

// SetUserWithdrawLimitPerCycle is a paid mutator transaction binding the contract method 0x0e8f3292.
//
// Solidity: function setUserWithdrawLimitPerCycle(uint256 _userWithdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawSession) SetUserWithdrawLimitPerCycle(_userWithdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.SetUserWithdrawLimitPerCycle(&_Withdraw.TransactOpts, _userWithdrawLimitPerCycle)
}

// SetUserWithdrawLimitPerCycle is a paid mutator transaction binding the contract method 0x0e8f3292.
//
// Solidity: function setUserWithdrawLimitPerCycle(uint256 _userWithdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawTransactorSession) SetUserWithdrawLimitPerCycle(_userWithdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.SetUserWithdrawLimitPerCycle(&_Withdraw.TransactOpts, _userWithdrawLimitPerCycle)
}

// SetWithdrawLimitPerCycle is a paid mutator transaction binding the contract method 0x96e46a13.
//
// Solidity: function setWithdrawLimitPerCycle(uint256 _withdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawTransactor) SetWithdrawLimitPerCycle(opts *bind.TransactOpts, _withdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "setWithdrawLimitPerCycle", _withdrawLimitPerCycle)
}

// SetWithdrawLimitPerCycle is a paid mutator transaction binding the contract method 0x96e46a13.
//
// Solidity: function setWithdrawLimitPerCycle(uint256 _withdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawSession) SetWithdrawLimitPerCycle(_withdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.SetWithdrawLimitPerCycle(&_Withdraw.TransactOpts, _withdrawLimitPerCycle)
}

// SetWithdrawLimitPerCycle is a paid mutator transaction binding the contract method 0x96e46a13.
//
// Solidity: function setWithdrawLimitPerCycle(uint256 _withdrawLimitPerCycle) returns()
func (_Withdraw *WithdrawTransactorSession) SetWithdrawLimitPerCycle(_withdrawLimitPerCycle *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.SetWithdrawLimitPerCycle(&_Withdraw.TransactOpts, _withdrawLimitPerCycle)
}

// Unstake is a paid mutator transaction binding the contract method 0x2e17de78.
//
// Solidity: function unstake(uint256 _rEthAmount) returns()
func (_Withdraw *WithdrawTransactor) Unstake(opts *bind.TransactOpts, _rEthAmount *big.Int) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "unstake", _rEthAmount)
}

// Unstake is a paid mutator transaction binding the contract method 0x2e17de78.
//
// Solidity: function unstake(uint256 _rEthAmount) returns()
func (_Withdraw *WithdrawSession) Unstake(_rEthAmount *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.Unstake(&_Withdraw.TransactOpts, _rEthAmount)
}

// Unstake is a paid mutator transaction binding the contract method 0x2e17de78.
//
// Solidity: function unstake(uint256 _rEthAmount) returns()
func (_Withdraw *WithdrawTransactorSession) Unstake(_rEthAmount *big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.Unstake(&_Withdraw.TransactOpts, _rEthAmount)
}

// Withdraw is a paid mutator transaction binding the contract method 0x983d95ce.
//
// Solidity: function withdraw(uint256[] _withdrawIndexList) returns()
func (_Withdraw *WithdrawTransactor) Withdraw(opts *bind.TransactOpts, _withdrawIndexList []*big.Int) (*types.Transaction, error) {
	return _Withdraw.contract.Transact(opts, "withdraw", _withdrawIndexList)
}

// Withdraw is a paid mutator transaction binding the contract method 0x983d95ce.
//
// Solidity: function withdraw(uint256[] _withdrawIndexList) returns()
func (_Withdraw *WithdrawSession) Withdraw(_withdrawIndexList []*big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.Withdraw(&_Withdraw.TransactOpts, _withdrawIndexList)
}

// Withdraw is a paid mutator transaction binding the contract method 0x983d95ce.
//
// Solidity: function withdraw(uint256[] _withdrawIndexList) returns()
func (_Withdraw *WithdrawTransactorSession) Withdraw(_withdrawIndexList []*big.Int) (*types.Transaction, error) {
	return _Withdraw.Contract.Withdraw(&_Withdraw.TransactOpts, _withdrawIndexList)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_Withdraw *WithdrawTransactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Withdraw.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_Withdraw *WithdrawSession) Receive() (*types.Transaction, error) {
	return _Withdraw.Contract.Receive(&_Withdraw.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_Withdraw *WithdrawTransactorSession) Receive() (*types.Transaction, error) {
	return _Withdraw.Contract.Receive(&_Withdraw.TransactOpts)
}

// WithdrawEtherDepositedIterator is returned from FilterEtherDeposited and is used to iterate over the raw logs and unpacked data for EtherDeposited events raised by the Withdraw contract.
type WithdrawEtherDepositedIterator struct {
	Event *WithdrawEtherDeposited // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *WithdrawEtherDepositedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(WithdrawEtherDeposited)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(WithdrawEtherDeposited)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *WithdrawEtherDepositedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *WithdrawEtherDepositedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// WithdrawEtherDeposited represents a EtherDeposited event raised by the Withdraw contract.
type WithdrawEtherDeposited struct {
	From   common.Address
	Amount *big.Int
	Time   *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterEtherDeposited is a free log retrieval operation binding the contract event 0xef51b4c870b8b0100eae2072e91db01222a303072af3728e58c9d4d2da33127f.
//
// Solidity: event EtherDeposited(address indexed from, uint256 amount, uint256 time)
func (_Withdraw *WithdrawFilterer) FilterEtherDeposited(opts *bind.FilterOpts, from []common.Address) (*WithdrawEtherDepositedIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Withdraw.contract.FilterLogs(opts, "EtherDeposited", fromRule)
	if err != nil {
		return nil, err
	}
	return &WithdrawEtherDepositedIterator{contract: _Withdraw.contract, event: "EtherDeposited", logs: logs, sub: sub}, nil
}

// WatchEtherDeposited is a free log subscription operation binding the contract event 0xef51b4c870b8b0100eae2072e91db01222a303072af3728e58c9d4d2da33127f.
//
// Solidity: event EtherDeposited(address indexed from, uint256 amount, uint256 time)
func (_Withdraw *WithdrawFilterer) WatchEtherDeposited(opts *bind.WatchOpts, sink chan<- *WithdrawEtherDeposited, from []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Withdraw.contract.WatchLogs(opts, "EtherDeposited", fromRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(WithdrawEtherDeposited)
				if err := _Withdraw.contract.UnpackLog(event, "EtherDeposited", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseEtherDeposited is a log parse operation binding the contract event 0xef51b4c870b8b0100eae2072e91db01222a303072af3728e58c9d4d2da33127f.
//
// Solidity: event EtherDeposited(address indexed from, uint256 amount, uint256 time)
func (_Withdraw *WithdrawFilterer) ParseEtherDeposited(log types.Log) (*WithdrawEtherDeposited, error) {
	event := new(WithdrawEtherDeposited)
	if err := _Withdraw.contract.UnpackLog(event, "EtherDeposited", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// WithdrawNotifyValidatorExitIterator is returned from FilterNotifyValidatorExit and is used to iterate over the raw logs and unpacked data for NotifyValidatorExit events raised by the Withdraw contract.
type WithdrawNotifyValidatorExitIterator struct {
	Event *WithdrawNotifyValidatorExit // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *WithdrawNotifyValidatorExitIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(WithdrawNotifyValidatorExit)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(WithdrawNotifyValidatorExit)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *WithdrawNotifyValidatorExitIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *WithdrawNotifyValidatorExitIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// WithdrawNotifyValidatorExit represents a NotifyValidatorExit event raised by the Withdraw contract.
type WithdrawNotifyValidatorExit struct {
	WithdrawCycle             *big.Int
	EjectedStartWithdrawCycle *big.Int
	EjectedValidators         []*big.Int
	Raw                       types.Log // Blockchain specific contextual infos
}

// FilterNotifyValidatorExit is a free log retrieval operation binding the contract event 0xb83477449e27b4bab4f28c938d033b953557d6a1b9b4469a43d229f78ed6e55c.
//
// Solidity: event NotifyValidatorExit(uint256 withdrawCycle, uint256 ejectedStartWithdrawCycle, uint256[] ejectedValidators)
func (_Withdraw *WithdrawFilterer) FilterNotifyValidatorExit(opts *bind.FilterOpts) (*WithdrawNotifyValidatorExitIterator, error) {

	logs, sub, err := _Withdraw.contract.FilterLogs(opts, "NotifyValidatorExit")
	if err != nil {
		return nil, err
	}
	return &WithdrawNotifyValidatorExitIterator{contract: _Withdraw.contract, event: "NotifyValidatorExit", logs: logs, sub: sub}, nil
}

// WatchNotifyValidatorExit is a free log subscription operation binding the contract event 0xb83477449e27b4bab4f28c938d033b953557d6a1b9b4469a43d229f78ed6e55c.
//
// Solidity: event NotifyValidatorExit(uint256 withdrawCycle, uint256 ejectedStartWithdrawCycle, uint256[] ejectedValidators)
func (_Withdraw *WithdrawFilterer) WatchNotifyValidatorExit(opts *bind.WatchOpts, sink chan<- *WithdrawNotifyValidatorExit) (event.Subscription, error) {

	logs, sub, err := _Withdraw.contract.WatchLogs(opts, "NotifyValidatorExit")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(WithdrawNotifyValidatorExit)
				if err := _Withdraw.contract.UnpackLog(event, "NotifyValidatorExit", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseNotifyValidatorExit is a log parse operation binding the contract event 0xb83477449e27b4bab4f28c938d033b953557d6a1b9b4469a43d229f78ed6e55c.
//
// Solidity: event NotifyValidatorExit(uint256 withdrawCycle, uint256 ejectedStartWithdrawCycle, uint256[] ejectedValidators)
func (_Withdraw *WithdrawFilterer) ParseNotifyValidatorExit(log types.Log) (*WithdrawNotifyValidatorExit, error) {
	event := new(WithdrawNotifyValidatorExit)
	if err := _Withdraw.contract.UnpackLog(event, "NotifyValidatorExit", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// WithdrawProposalExecutedIterator is returned from FilterProposalExecuted and is used to iterate over the raw logs and unpacked data for ProposalExecuted events raised by the Withdraw contract.
type WithdrawProposalExecutedIterator struct {
	Event *WithdrawProposalExecuted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *WithdrawProposalExecutedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(WithdrawProposalExecuted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(WithdrawProposalExecuted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *WithdrawProposalExecutedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *WithdrawProposalExecutedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// WithdrawProposalExecuted represents a ProposalExecuted event raised by the Withdraw contract.
type WithdrawProposalExecuted struct {
	ProposalId [32]byte
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterProposalExecuted is a free log retrieval operation binding the contract event 0x7b1bcf1ccf901a11589afff5504d59fd0a53780eed2a952adade0348985139e0.
//
// Solidity: event ProposalExecuted(bytes32 indexed proposalId)
func (_Withdraw *WithdrawFilterer) FilterProposalExecuted(opts *bind.FilterOpts, proposalId [][32]byte) (*WithdrawProposalExecutedIterator, error) {

	var proposalIdRule []interface{}
	for _, proposalIdItem := range proposalId {
		proposalIdRule = append(proposalIdRule, proposalIdItem)
	}

	logs, sub, err := _Withdraw.contract.FilterLogs(opts, "ProposalExecuted", proposalIdRule)
	if err != nil {
		return nil, err
	}
	return &WithdrawProposalExecutedIterator{contract: _Withdraw.contract, event: "ProposalExecuted", logs: logs, sub: sub}, nil
}

// WatchProposalExecuted is a free log subscription operation binding the contract event 0x7b1bcf1ccf901a11589afff5504d59fd0a53780eed2a952adade0348985139e0.
//
// Solidity: event ProposalExecuted(bytes32 indexed proposalId)
func (_Withdraw *WithdrawFilterer) WatchProposalExecuted(opts *bind.WatchOpts, sink chan<- *WithdrawProposalExecuted, proposalId [][32]byte) (event.Subscription, error) {

	var proposalIdRule []interface{}
	for _, proposalIdItem := range proposalId {
		proposalIdRule = append(proposalIdRule, proposalIdItem)
	}

	logs, sub, err := _Withdraw.contract.WatchLogs(opts, "ProposalExecuted", proposalIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(WithdrawProposalExecuted)
				if err := _Withdraw.contract.UnpackLog(event, "ProposalExecuted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseProposalExecuted is a log parse operation binding the contract event 0x7b1bcf1ccf901a11589afff5504d59fd0a53780eed2a952adade0348985139e0.
//
// Solidity: event ProposalExecuted(bytes32 indexed proposalId)
func (_Withdraw *WithdrawFilterer) ParseProposalExecuted(log types.Log) (*WithdrawProposalExecuted, error) {
	event := new(WithdrawProposalExecuted)
	if err := _Withdraw.contract.UnpackLog(event, "ProposalExecuted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// WithdrawUnstakeIterator is returned from FilterUnstake and is used to iterate over the raw logs and unpacked data for Unstake events raised by the Withdraw contract.
type WithdrawUnstakeIterator struct {
	Event *WithdrawUnstake // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *WithdrawUnstakeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(WithdrawUnstake)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(WithdrawUnstake)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *WithdrawUnstakeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *WithdrawUnstakeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// WithdrawUnstake represents a Unstake event raised by the Withdraw contract.
type WithdrawUnstake struct {
	From          common.Address
	RethAmount    *big.Int
	EthAmount     *big.Int
	WithdrawIndex *big.Int
	Instantly     bool
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterUnstake is a free log retrieval operation binding the contract event 0xc7ccdcb2d25f572c6814e377dbb34ea4318a4b7d3cd890f5cfad699d75327c7c.
//
// Solidity: event Unstake(address indexed from, uint256 rethAmount, uint256 ethAmount, uint256 withdrawIndex, bool instantly)
func (_Withdraw *WithdrawFilterer) FilterUnstake(opts *bind.FilterOpts, from []common.Address) (*WithdrawUnstakeIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Withdraw.contract.FilterLogs(opts, "Unstake", fromRule)
	if err != nil {
		return nil, err
	}
	return &WithdrawUnstakeIterator{contract: _Withdraw.contract, event: "Unstake", logs: logs, sub: sub}, nil
}

// WatchUnstake is a free log subscription operation binding the contract event 0xc7ccdcb2d25f572c6814e377dbb34ea4318a4b7d3cd890f5cfad699d75327c7c.
//
// Solidity: event Unstake(address indexed from, uint256 rethAmount, uint256 ethAmount, uint256 withdrawIndex, bool instantly)
func (_Withdraw *WithdrawFilterer) WatchUnstake(opts *bind.WatchOpts, sink chan<- *WithdrawUnstake, from []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Withdraw.contract.WatchLogs(opts, "Unstake", fromRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(WithdrawUnstake)
				if err := _Withdraw.contract.UnpackLog(event, "Unstake", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUnstake is a log parse operation binding the contract event 0xc7ccdcb2d25f572c6814e377dbb34ea4318a4b7d3cd890f5cfad699d75327c7c.
//
// Solidity: event Unstake(address indexed from, uint256 rethAmount, uint256 ethAmount, uint256 withdrawIndex, bool instantly)
func (_Withdraw *WithdrawFilterer) ParseUnstake(log types.Log) (*WithdrawUnstake, error) {
	event := new(WithdrawUnstake)
	if err := _Withdraw.contract.UnpackLog(event, "Unstake", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// WithdrawVoteProposalIterator is returned from FilterVoteProposal and is used to iterate over the raw logs and unpacked data for VoteProposal events raised by the Withdraw contract.
type WithdrawVoteProposalIterator struct {
	Event *WithdrawVoteProposal // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *WithdrawVoteProposalIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(WithdrawVoteProposal)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(WithdrawVoteProposal)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *WithdrawVoteProposalIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *WithdrawVoteProposalIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// WithdrawVoteProposal represents a VoteProposal event raised by the Withdraw contract.
type WithdrawVoteProposal struct {
	ProposalId [32]byte
	Voter      common.Address
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterVoteProposal is a free log retrieval operation binding the contract event 0x3b58f01618556cdc5e9f7b0f1f6dccbac40024bc1043f589bd4a324e3414cfad.
//
// Solidity: event VoteProposal(bytes32 indexed proposalId, address voter)
func (_Withdraw *WithdrawFilterer) FilterVoteProposal(opts *bind.FilterOpts, proposalId [][32]byte) (*WithdrawVoteProposalIterator, error) {

	var proposalIdRule []interface{}
	for _, proposalIdItem := range proposalId {
		proposalIdRule = append(proposalIdRule, proposalIdItem)
	}

	logs, sub, err := _Withdraw.contract.FilterLogs(opts, "VoteProposal", proposalIdRule)
	if err != nil {
		return nil, err
	}
	return &WithdrawVoteProposalIterator{contract: _Withdraw.contract, event: "VoteProposal", logs: logs, sub: sub}, nil
}

// WatchVoteProposal is a free log subscription operation binding the contract event 0x3b58f01618556cdc5e9f7b0f1f6dccbac40024bc1043f589bd4a324e3414cfad.
//
// Solidity: event VoteProposal(bytes32 indexed proposalId, address voter)
func (_Withdraw *WithdrawFilterer) WatchVoteProposal(opts *bind.WatchOpts, sink chan<- *WithdrawVoteProposal, proposalId [][32]byte) (event.Subscription, error) {

	var proposalIdRule []interface{}
	for _, proposalIdItem := range proposalId {
		proposalIdRule = append(proposalIdRule, proposalIdItem)
	}

	logs, sub, err := _Withdraw.contract.WatchLogs(opts, "VoteProposal", proposalIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(WithdrawVoteProposal)
				if err := _Withdraw.contract.UnpackLog(event, "VoteProposal", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseVoteProposal is a log parse operation binding the contract event 0x3b58f01618556cdc5e9f7b0f1f6dccbac40024bc1043f589bd4a324e3414cfad.
//
// Solidity: event VoteProposal(bytes32 indexed proposalId, address voter)
func (_Withdraw *WithdrawFilterer) ParseVoteProposal(log types.Log) (*WithdrawVoteProposal, error) {
	event := new(WithdrawVoteProposal)
	if err := _Withdraw.contract.UnpackLog(event, "VoteProposal", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// WithdrawWithdrawIterator is returned from FilterWithdraw and is used to iterate over the raw logs and unpacked data for Withdraw events raised by the Withdraw contract.
type WithdrawWithdrawIterator struct {
	Event *WithdrawWithdraw // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *WithdrawWithdrawIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(WithdrawWithdraw)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(WithdrawWithdraw)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *WithdrawWithdrawIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *WithdrawWithdrawIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// WithdrawWithdraw represents a Withdraw event raised by the Withdraw contract.
type WithdrawWithdraw struct {
	From              common.Address
	WithdrawIndexList []*big.Int
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterWithdraw is a free log retrieval operation binding the contract event 0x67e9df8b3c7743c9f1b625ba4f2b4e601206dbd46ed5c33c85a1242e4d23a2d1.
//
// Solidity: event Withdraw(address indexed from, uint256[] withdrawIndexList)
func (_Withdraw *WithdrawFilterer) FilterWithdraw(opts *bind.FilterOpts, from []common.Address) (*WithdrawWithdrawIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Withdraw.contract.FilterLogs(opts, "Withdraw", fromRule)
	if err != nil {
		return nil, err
	}
	return &WithdrawWithdrawIterator{contract: _Withdraw.contract, event: "Withdraw", logs: logs, sub: sub}, nil
}

// WatchWithdraw is a free log subscription operation binding the contract event 0x67e9df8b3c7743c9f1b625ba4f2b4e601206dbd46ed5c33c85a1242e4d23a2d1.
//
// Solidity: event Withdraw(address indexed from, uint256[] withdrawIndexList)
func (_Withdraw *WithdrawFilterer) WatchWithdraw(opts *bind.WatchOpts, sink chan<- *WithdrawWithdraw, from []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Withdraw.contract.WatchLogs(opts, "Withdraw", fromRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(WithdrawWithdraw)
				if err := _Withdraw.contract.UnpackLog(event, "Withdraw", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseWithdraw is a log parse operation binding the contract event 0x67e9df8b3c7743c9f1b625ba4f2b4e601206dbd46ed5c33c85a1242e4d23a2d1.
//
// Solidity: event Withdraw(address indexed from, uint256[] withdrawIndexList)
func (_Withdraw *WithdrawFilterer) ParseWithdraw(log types.Log) (*WithdrawWithdraw, error) {
	event := new(WithdrawWithdraw)
	if err := _Withdraw.contract.UnpackLog(event, "Withdraw", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
