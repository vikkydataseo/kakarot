// SPDX-License-Identifier: MIT

%lang starknet

// Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc

// Local dependencies
from kakarot.library import Kakarot
from kakarot.model import model
from kakarot.stack import Stack
from kakarot.interfaces.interfaces import IEvmContract
from kakarot.memory import Memory
from kakarot.execution_context import ExecutionContext
from starkware.cairo.common.dict import DictAccess

// Constructor
@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    owner: felt, native_token_address_: felt, evm_contract_class_hash: felt
) {
    return Kakarot.constructor(owner, native_token_address_, evm_contract_class_hash);
}

// @notice Execute EVM bytecode
// @dev Executes a provided array of evm opcodes/bytes
// @param value The deposited value by the instruction/transaction responsible for this execution
// @param bytecode_len The bytecode length
// @param bytecode The bytecode to be executed
// @param calldata_len The calldata length
// @param calldata The calldata which can be referenced by the bytecode
// @return stack_len The length of the stack
// @return stack The EVM stack content
// @return memory_len The memory length
// @return memory The EVM memory content
// @return gas_used The total amount of gas used to execute the given bytecode
@view
func execute{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(value: felt, bytecode_len: felt, bytecode: felt*, calldata_len: felt, calldata: felt*) -> (
    stack_len: felt,
    stack: Uint256*,
    memory_changes_len: felt,
    memory_changes: felt*,
    memory_real_len: felt,
    gas_used: felt,
) {
    alloc_locals;
    local call_context: model.CallContext* = new model.CallContext(
        bytecode=bytecode, bytecode_len=bytecode_len, calldata=calldata, calldata_len=calldata_len, value=value
        );
    let summary = Kakarot.execute(call_context);
    let len = Stack.len(summary.stack);
    return (
        stack_len=len,
        stack=summary.stack.elements,
        memory_changes_len=summary.memory.squashed_end - summary.memory.squashed_start,
        memory_changes=summary.memory.squashed_start,
        memory_real_len=summary.memory.bytes_len,
        gas_used=summary.gas_used,
    );
}

// @notice execute bytecode of a given contract account
// @dev reads the bytecode content of an contract account and then executes it
// @param address The address of the contract whose bytecode will be executed
// @param value The deposited value by the instruction/transaction responsible for this execution
// @param calldata_len The calldata length
// @param calldata The calldata which contains the entry point and method parameters
// @return stack_len The length of the stack
// @return stack The EVM stack content
// @return memory_len The memory length
// @return memory The EVM memory content
// @return gas_used The total amount of gas used to execute the given bytecode
@external
func execute_at_address{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(address: felt, value: felt, calldata_len: felt, calldata: felt*) -> (
    stack_len: felt,
    stack: Uint256*,
    memory_changes_len: felt,
    memory_changes: felt*,
    memory_real_len: felt,
    evm_contract_address: felt,
    starknet_contract_address: felt,
    return_data_len: felt,
    return_data: felt*,
) {
    alloc_locals;
    let summary = Kakarot.execute_at_address(
        address=address, calldata_len=calldata_len, calldata=calldata, value=value
    );

    let len = Stack.len(summary.stack);
    return (
        stack_len=len,
        stack=summary.stack.elements,
        memory_changes_len=summary.memory.squashed_end - summary.memory.squashed_start,
        memory_changes=summary.memory.squashed_start,
        memory_real_len=summary.memory.bytes_len,
        evm_contract_address=summary.evm_contract_address,
        starknet_contract_address=summary.starknet_contract_address,
        return_data_len=summary.return_data_len,
        return_data=summary.return_data,
    );
}

// @notice Set the account registry used by kakarot
// @dev Set the account regestry which will be used to convert
//      given starknet addresses to evm addresses and vice versa
// @param registry_address_ The address of the new account registry contract
@external
func set_account_registry{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    registry_address_: felt
) {
    return Kakarot.set_account_registry(registry_address_);
}

// @notice Get the account registry used by kakarot
// @return address The address of the current account registry contract
@view
func get_account_registry{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    address: felt
) {
    return Kakarot.get_account_registry();
}

// @notice Set the native token used by kakarot
// @dev Set the native token which will emulate the role of ETH on Ethereum
// @param native_token_address_ The address of the native token
@external
func set_native_token{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    native_token_address_: felt
) {
    return Kakarot.set_native_token(native_token_address_);
}

// @notice Deploy a new contract account and execute constructor
// @param bytes_len: the constructor + contract bytecode lenght
// @param bytes: the constructor + contract bytecode
// @return evm_contract_address The evm address that is mapped to the newly deployed starknet contract address
// @return starknet_contract_address The newly deployed starknet contract address
@external
func deploy{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(bytecode_len: felt, bytecode: felt*) -> (
    evm_contract_address: felt, starknet_contract_address: felt
) {
    return Kakarot.deploy(bytecode_len, bytecode);
}
