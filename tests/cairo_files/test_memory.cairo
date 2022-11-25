// SPDX-License-Identifier: MIT

%lang starknet

// Starkware dependencies
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.uint256 import Uint256, assert_uint256_eq
from starkware.cairo.common.math import assert_nn

// Local dependencies
from utils.utils import Helpers
from kakarot.model import model
from kakarot.memory import Memory

@external
func test__init__should_return_an_empty_memory{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    // When
    let result: model.Memory* = Memory.init();

    // Then
    assert result.bytes_len = 0;
    return ();
}

@external
func test__len__should_return_the_length_of_the_memory{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    // Given
    let memory: model.Memory* = Memory.init();

    // When
    let result: felt = memory.bytes_len;

    // Then
    assert result = 0;
    return ();
}

@external
func test__store__should_add_an_element_to_the_memory{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    // Given
    let memory: model.Memory* = Memory.init();

    // When
    let result: model.Memory* = Memory.store(memory, Uint256(1, 0), 0);

    // Then
    let len: felt = result.bytes_len;
    assert len = 32;
    return ();
}

@external
func test__load__should_load_an_element_from_the_memory{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    alloc_locals;
    // Given
    let memory: model.Memory* = Memory.init();
    // In the memory, the following values are stored in the order 1, 2, 3, 4 (Big Endian)
    let memory: model.Memory* = Memory.store(memory, Uint256(low=2, high=1), 0);
    let memory: model.Memory* = Memory.store(memory, Uint256(low=4, high=3), 32);

    // When
    let (memory, result) = Memory.load(memory, 0);

    // Then
    assert_uint256_eq(result, Uint256(2, 1));

    // When
    let (memory, result) = Memory.load(memory, 32);

    // Then
    assert_uint256_eq(result, Uint256(4, 3));

    // When
    let (memory, result) = Memory.load(memory, 16);

    // Then
    assert_uint256_eq(result, Uint256(3, 2));

    return ();
}

@external
func test__load__should_load_an_element_from_the_memory_with_offset{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(offset: felt, low: felt, high: felt) {
    alloc_locals;
    // Given
    let memory: model.Memory* = Memory.init();
    let memory: model.Memory* = Memory.store(memory, Uint256(low=2, high=1), 0);
    let memory: model.Memory* = Memory.store(memory, Uint256(low=4, high=3), 32);

    // When
    let (memory, result) = Memory.load(memory, offset);

    // Then
    assert_uint256_eq(result, Uint256(low, high));

    return ();
}

@external
func test__load__should_fail__when_out_of_memory{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    // Given
    let memory: model.Memory* = Memory.init();
    let memory: model.Memory* = Memory.store(memory, Uint256(1, 0), 0);

    // When & Then
    let (memory, result) = Memory.load(memory, 2);
    return ();
}

@external
func test__expand__should_return_the_same_memory_and_no_cost{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    // Given
    alloc_locals;
    let memory = Memory.init();
    let memory = Memory.store(self=memory, element=Uint256(1, 0), offset=0);

    // When
    let (memory, cost) = Memory.expand(self=memory, length=0);

    // Then
    assert cost = 0;
    assert memory.bytes_len = 32;
    let (memory, value) = Memory.load(self=memory, offset=0);
    assert value = Uint256(1, 0);

    return ();
}

@external
func test__expand__should_return_expanded_memory_and_cost{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    // Given
    alloc_locals;
    let memory = Memory.init();
    let memory = Memory.store(self=memory, element=Uint256(1, 0), offset=0);

    // When
    let (memory, cost) = Memory.expand(self=memory, length=1);

    // Then
    assert_nn(cost);
    assert memory.bytes_len = 33;
    let (memory, value) = Memory.load(self=memory, offset=0);
    assert value = Uint256(1, 0);

    return ();
}

@external
func test__ensure_length__should_return_the_same_memory_and_no_cost{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    // Given
    alloc_locals;
    let memory = Memory.init();
    let memory = Memory.store(self=memory, element=Uint256(1, 0), offset=0);

    // When
    let (memory, cost) = Memory.ensure_length(self=memory, length=1);

    // Then
    assert cost = 0;
    assert memory.bytes_len = 32;
    let (memory, value) = Memory.load(self=memory, offset=0);
    assert value = Uint256(1, 0);

    return ();
}

@external
func test__ensure_length__should_return_expanded_memory_and_cost{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    // Given
    alloc_locals;
    let memory = Memory.init();
    let memory = Memory.store(self=memory, element=Uint256(1, 0), offset=0);

    // When
    let (memory, cost) = Memory.ensure_length(self=memory, length=33);

    // Then
    assert_nn(cost);
    assert memory.bytes_len = 33;
    let (memory, value) = Memory.load(self=memory, offset=0);
    assert value = Uint256(1, 0);

    return ();
}

// @external
// func test__store_n__load_n{
//     syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
// }(store_offset: felt, store_n_bytes: felt, store_bytes: felt*, load_offset: felt, load_n_bytes: felt) -> (load_bytes: felt*) {
//     // Given
//     alloc_locals;
//     let memory = Memory.init();
//     let memory = Memory.store_n(self=memory, element_len=store_n_bytes, element=store_bytes, offset=store_offset);

// // When
//     let (data: felt*) = alloc();
//     let memory = Memory.load_n(self=memory, element_len=load_n_bytes, element=load_

// // Then
//     assert_nn(cost);
//     assert memory.bytes_len = 33;
//     let (memory, value) = Memory.load(self=memory, offset=0);
//     assert value = Uint256(1, 0);

// return ();
// }
