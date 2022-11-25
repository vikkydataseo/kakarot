// SPDX-License-Identifier: MIT

%lang starknet

// StarkWare dependencies
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.dict import DictAccess

namespace model {
    struct Stack {
        elements: Uint256*,
        raw_len: felt,
    }

    struct Memory {
        // TODO: Save word_dict_start in the initialization only, to avoid unnecessary copies.
        // Dictionary fomr chunk index to chunk vaue for 16B chunks.
        // See `memory.cairo`.
        word_dict_start: DictAccess*,
        word_dict: DictAccess*,
        bytes_len: felt,
    }

    struct CallContext {
        bytecode: felt*,
        bytecode_len: felt,
        calldata: felt*,
        calldata_len: felt,
        value: felt,
    }

    struct ExecutionContext {
        call_context: CallContext*,
        program_counter: felt,
        stopped: felt,
        return_data: felt*,
        return_data_len: felt,
        stack: Stack*,
        memory: Memory*,
        gas_used: felt,
        gas_limit: felt,
        intrinsic_gas_cost: felt,
        starknet_contract_address: felt,
        evm_contract_address: felt,
    }
}
