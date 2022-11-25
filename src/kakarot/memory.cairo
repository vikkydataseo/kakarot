// SPDX-License-Identifier: MIT

%lang starknet

// Starkware dependencies
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.dict import DictAccess, dict_read, dict_write
from starkware.cairo.common.default_dict import default_dict_new, default_dict_finalize
from starkware.cairo.common.math import (
    split_int,
    unsigned_div_rem,
    assert_le,
    assert_nn_le,
    assert_nn,
)
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.registers import get_label_location

// Internal dependencies
from kakarot.model import model
from utils.utils import Helpers

// @title Memory related functions.
// @notice This file contains functions related to the memory.
// @dev The memory is a region that only exists during the smart contract execution, and is accessed
// @dev with a byte offset.
// @dev While all the 32-byte address space is available and initialized to 0, the
// @dev size is counted with the highest address that was accessed.
// @dev It is generally read and written with `MLOAD` and `MSTORE` instructions,
// @dev but is also used by other instructions like `CREATE` or `EXTCODECOPY`.
// @author @abdelhamidbakhta
// @custom:namespace Memory
// @custom:model model.Memory
namespace Memory {
    // The memory representation is a sequence of 128bit (16B) chunks,
    // stored as a dictionary from chunk_index to chunk_value.
    // Each chunk should be read as big endian representation of 16 bytes.

    struct Summary {
        bytes_len: felt,
        squashed_start: DictAccess*,
        squashed_end: DictAccess*,
    }

    func load_word(len: felt, ptr: felt*) -> felt {
        if (len == 0) {
            return 0;
        }
        tempvar current = 0;

        // len, ptr, ?, ?, current
        loop:
        let len = [ap - 5];
        let ptr = cast([ap - 4], felt*);
        let current = [ap - 1];

        tempvar len = len - 1;
        tempvar ptr = ptr + 1;
        tempvar loaded = [ptr - 1];
        tempvar tmp = current * 256;
        tempvar current = tmp + loaded;

        static_assert len == [ap - 5];
        static_assert ptr == [ap - 4];
        static_assert current == [ap - 1];
        jmp loop if len != 0;

        return current;
    }

    func div_rem{range_check_ptr}(value, div) -> (q: felt, r: felt) {
        if (div == 2 ** 128) {
            return (0, value);
        }

        // Copied from unsigned_div_rem.
        let r = [range_check_ptr];
        let q = [range_check_ptr + 1];
        let range_check_ptr = range_check_ptr + 2;
        %{
            from starkware.cairo.common.math_utils import assert_integer
            assert_integer(ids.div)
            assert 0 < ids.div <= PRIME // range_check_builtin.bound, \
                f'div={hex(ids.div)} is out of the valid range.'
            ids.q, ids.r = divmod(ids.value, ids.div)
        %}
        assert_le(r, div - 1);

        assert value = q * div + r;
        return (q, r);
    }

    // / 256 ** (16 - i).
    func pow256_rev(i: felt) -> felt {
        let (pow256_rev_address) = get_label_location(pow256_rev_table);
        return pow256_rev_address[i];

        pow256_rev_table:
        dw 340282366920938463463374607431768211456;
        dw 1329227995784915872903807060280344576;
        dw 5192296858534827628530496329220096;
        dw 20282409603651670423947251286016;
        dw 79228162514264337593543950336;
        dw 309485009821345068724781056;
        dw 1208925819614629174706176;
        dw 4722366482869645213696;
        dw 18446744073709551616;
        dw 72057594037927936;
        dw 281474976710656;
        dw 1099511627776;
        dw 4294967296;
        dw 16777216;
        dw 65536;
        dw 256;
        dw 1;
    }

    // @notice Initialize the memory.
    // @return The pointer to the memory.
    func init() -> model.Memory* {
        alloc_locals;
        let (word_dict_start: DictAccess*) = default_dict_new(0);
        return new model.Memory(
            word_dict_start=word_dict_start,
            word_dict=word_dict_start,
            bytes_len=0);
    }

    func finalize{range_check_ptr}(self: model.Memory*) -> Summary* {
        let (squashed_start, squashed_end) = default_dict_finalize(
            self.word_dict_start, self.word_dict, 0
        );
        return new Summary(
            bytes_len=self.bytes_len, squashed_start=squashed_start, squashed_end=squashed_end
            );
    }

    // @notice Store an element into the memory.
    // @param self - The pointer to the memory.
    // @param element - The element to push.
    // @param offset - The offset to store the element at.
    // @return The new pointer to the memory.
    func store{range_check_ptr}(
        self: model.Memory*, element: Uint256, offset: felt
    ) -> model.Memory* {
        let word_dict = self.word_dict;

        // Compute new bytes_len.
        let new_min_bytes_len = offset + 32;
        let fits = is_le(new_min_bytes_len, self.bytes_len);
        if (fits == 0) {
            tempvar new_bytes_len = new_min_bytes_len;
        } else {
            tempvar new_bytes_len = self.bytes_len;
        }

        // Check alignment of offset to 16B chunks.
        let (chunk_index, offset_in_chunk) = unsigned_div_rem(offset, 16);

        if (offset_in_chunk == 0) {
            // Offset is aligned. This is the simplest and most efficient case,
            // so we optimize for it. Note that no locals were allocated at all.
            dict_write{dict_ptr=word_dict}(chunk_index, element.high);
            dict_write{dict_ptr=word_dict}(chunk_index + 1, element.low);
            return (new model.Memory(
                word_dict_start=self.word_dict_start,
                word_dict=word_dict,
                bytes_len=new_bytes_len,
                ));
        }

        // Offset is misaligned.
        // |   W0   |   W1   |   w2   |
        //     |  EL_H  |  EL_L  |
        // ^---^
        //   |-- mask = 256 ** offset_in_chunk

        // Compute mask.
        tempvar mask = pow256_rev(offset_in_chunk);
        let mask_c = 2 ** 128 / mask;

        // Split the 2 input 16B chunks at offset_in_chunk.
        let (el_hh, el_hl) = unsigned_div_rem(element.high, mask_c);
        let (el_lh, el_ll) = unsigned_div_rem(element.low, mask_c);

        // Read the words at chunk_index, chunk_index + 2.
        let (w0) = dict_read{dict_ptr=word_dict}(chunk_index);
        let (w2) = dict_read{dict_ptr=word_dict}(chunk_index + 2);

        // Compute the new words.
        let (w0_h, w0_l) = unsigned_div_rem(w0, mask);
        let (w2_h, w2_l) = unsigned_div_rem(w2, mask);
        let new_w0 = w0_h * mask + el_hh;
        let new_w1 = el_hl * mask + el_lh;
        let new_w2 = el_ll * mask + w2_l;

        // Write new words.
        dict_write{dict_ptr=word_dict}(chunk_index, new_w0);
        dict_write{dict_ptr=word_dict}(chunk_index + 1, new_w1);
        dict_write{dict_ptr=word_dict}(chunk_index + 2, new_w2);
        return (new model.Memory(
            word_dict_start=self.word_dict_start,
            word_dict=word_dict,
            bytes_len=new_bytes_len,
            ));
    }

    // @notice store_n Store N bytes into the memory.
    // @param self The pointer to the memory.
    // @param element_len byte length of the array to be saved on memory.
    // @param element pointer to the array that will be saved on memory.
    // @param offset The offset to store the element at.
    // @return The new pointer to the memory.
    func store_n{range_check_ptr}(
        self: model.Memory*, element_len: felt, element: felt*, offset: felt
    ) -> model.Memory* {
        alloc_locals;
        if (element_len == 0) {
            return self;
        }

        let word_dict = self.word_dict;

        // Compute new bytes_len.
        let new_min_bytes_len = offset + element_len;

        let (q, r) = unsigned_div_rem(new_min_bytes_len + 31, 32);
        local new_min_bytes_len = q * 32;

        let fits = is_le(new_min_bytes_len, self.bytes_len);
        local new_bytes_len;
        if (fits == 0) {
            new_bytes_len = new_min_bytes_len;
        } else {
            new_bytes_len = self.bytes_len;
        }

        // Check alignment of offset to 16B chunks.
        let (chunk_index_i, offset_in_chunk_i) = unsigned_div_rem(offset, 16);
        let (chunk_index_f, offset_in_chunk_f) = unsigned_div_rem(offset + element_len - 1, 16);
        tempvar offset_in_chunk_f = offset_in_chunk_f + 1;
        let mask_i = pow256_rev(offset_in_chunk_i);
        let mask_f = pow256_rev(offset_in_chunk_f);

        // Special case: within the same word.
        if (chunk_index_i == chunk_index_f) {
            let (w) = dict_read{dict_ptr=word_dict}(chunk_index_i);

            let (w_h, w_l) = div_rem(w, mask_i);
            let (w_lh, w_ll) = div_rem(w_l, mask_f);
            let x = load_word(element_len, element);
            let new_w = w_h * mask_i + x * mask_f + w_ll;
            dict_write{dict_ptr=word_dict}(chunk_index_i, new_w);
            return (new model.Memory(
                word_dict_start=self.word_dict_start,
                word_dict=word_dict,
                bytes_len=new_bytes_len));
        }

        // Otherwise.
        // Fill first word.
        let (w_i) = dict_read{dict_ptr=word_dict}(chunk_index_i);
        let (w_i_h, w_i_l) = div_rem(w_i, mask_i);
        let x_i = load_word(16 - offset_in_chunk_i, element);
        dict_write{dict_ptr=word_dict}(chunk_index_i, w_i_h * mask_i + x_i);

        // Fill last word.
        let (w_f) = dict_read{dict_ptr=word_dict}(chunk_index_f);
        let (w_f_h, w_f_l) = div_rem(w_f, mask_f);
        let x_f = load_word(offset_in_chunk_f, element + element_len - offset_in_chunk_f);
        dict_write{dict_ptr=word_dict}(chunk_index_f, x_f * mask_f + w_f_l);

        // Write blocks.
        let (word_dict) = store_aligned(
            word_dict, chunk_index_i + 1, chunk_index_f, element + 16 - offset_in_chunk_i
        );

        return (new model.Memory(
            word_dict_start=self.word_dict_start,
            word_dict=word_dict,
            bytes_len=new_bytes_len));
    }

    func store_aligned{range_check_ptr}(
        word_dict: DictAccess*, chunk_index: felt, chunk_index_f: felt, element: felt*
    ) -> (word_dict: DictAccess*) {
        if (chunk_index == chunk_index_f) {
            return (word_dict=word_dict,);
        }
        let current = (
            element[0] * 256 ** 15 +
            element[1] * 256 ** 14 +
            element[2] * 256 ** 13 +
            element[3] * 256 ** 12 +
            element[4] * 256 ** 11 +
            element[5] * 256 ** 10 +
            element[6] * 256 ** 9 +
            element[7] * 256 ** 8 +
            element[8] * 256 ** 7 +
            element[9] * 256 ** 6 +
            element[10] * 256 ** 5 +
            element[11] * 256 ** 4 +
            element[12] * 256 ** 3 +
            element[13] * 256 ** 2 +
            element[14] * 256 ** 1 +
            element[15] * 256 ** 0);
        dict_write{dict_ptr=word_dict}(chunk_index, current);
        return store_aligned(
            word_dict=word_dict,
            chunk_index=chunk_index + 1,
            chunk_index_f=chunk_index_f,
            element=&element[16],
        );
    }

    // @notice Load an element from the memory.
    // @param self - The pointer to the memory.
    // @param offset - The offset to load the element from.
    // @param n - The number of bytes to load from memory.
    // @return The new pointer to the memory.
    // @return The loaded element.
    func load{range_check_ptr}(self: model.Memory*, offset: felt) -> (model.Memory*, Uint256) {
        let word_dict = self.word_dict;

        // Check alignment of offset to 16B chunks.
        let (chunk_index, offset_in_chunk) = unsigned_div_rem(offset, 16);

        if (offset_in_chunk == 0) {
            // Offset is aligned. This is the simplest and most efficient case,
            // so we optimize for it. Note that no locals were allocated at all.
            let (el_h) = dict_read{dict_ptr=word_dict}(chunk_index);
            let (el_l) = dict_read{dict_ptr=word_dict}(chunk_index + 1);
            return (
                new model.Memory(
                word_dict_start=self.word_dict_start,
                word_dict=word_dict,
                bytes_len=self.bytes_len,
                ),
                Uint256(low=el_l, high=el_h),
            );
        }

        // Offset is misaligned.
        // |   W0   |   W1   |   w2   |
        //     |  EL_H  |  EL_L  |
        //      ^---^
        //         |-- mask = 256 ** offset_in_chunk

        // Compute mask.
        tempvar mask = pow256_rev(offset_in_chunk);
        tempvar mask_c = 2 ** 128 / mask;

        // Read words.
        let (w0) = dict_read{dict_ptr=word_dict}(chunk_index);
        let (w1) = dict_read{dict_ptr=word_dict}(chunk_index + 1);
        let (w2) = dict_read{dict_ptr=word_dict}(chunk_index + 2);

        // Compute element words.
        let (w0_h, w0_l) = unsigned_div_rem(w0, mask);
        let (w1_h, w1_l) = unsigned_div_rem(w1, mask);
        let (w2_h, w2_l) = unsigned_div_rem(w2, mask);
        let el_h = w0_l * mask_c + w1_h;
        let el_l = w1_l * mask_c + w2_h;
        return (
            new model.Memory(
            word_dict_start=self.word_dict_start,
            word_dict=word_dict,
            bytes_len=self.bytes_len,
            ),
            Uint256(low=el_l, high=el_h),
        );
    }

    func load_n{range_check_ptr}(
        self: model.Memory*, element_len: felt, element: felt*, offset: felt
    ) -> model.Memory* {
        alloc_locals;
        if (element_len == 0) {
            return self;
        }

        let word_dict = self.word_dict;

        // Check alignment of offset to 16B chunks.
        let (chunk_index_i, offset_in_chunk_i) = unsigned_div_rem(offset, 16);
        let (chunk_index_f, offset_in_chunk_f) = unsigned_div_rem(offset + element_len - 1, 16);
        tempvar offset_in_chunk_f = offset_in_chunk_f + 1;
        let mask_i = pow256_rev(offset_in_chunk_i);
        let mask_f = pow256_rev(offset_in_chunk_f);

        // Special case: within the same word.
        if (chunk_index_i == chunk_index_f) {
            let (w) = dict_read{dict_ptr=word_dict}(chunk_index_i);
            let (w_h, w_l) = div_rem(w, mask_i);
            let (w_lh, w_ll) = div_rem(w_l, mask_f);
            split_word(w_lh, element_len, element);
            return (new model.Memory(
                word_dict_start=self.word_dict_start,
                word_dict=word_dict,
                bytes_len=self.bytes_len));
        }

        // Otherwise.
        // Get first word.
        let (w_i) = dict_read{dict_ptr=word_dict}(chunk_index_i);
        let (w_i_h, w_i_l) = div_rem(w_i, mask_i);

        split_word(w_i_l, 16 - offset_in_chunk_i, element);

        // Get last word.
        let (w_f) = dict_read{dict_ptr=word_dict}(chunk_index_f);
        let (w_f_h, w_f_l) = div_rem(w_f, mask_f);
        split_word(w_f_h, offset_in_chunk_f, element + element_len - offset_in_chunk_f);

        // Get blocks.
        let (word_dict) = get_aligned(
            word_dict, chunk_index_i + 1, chunk_index_f, element + 16 - offset_in_chunk_i
        );

        return (new model.Memory(
            word_dict_start=self.word_dict_start,
            word_dict=word_dict,
            bytes_len=self.bytes_len));
    }

    func get_aligned{range_check_ptr}(
        word_dict: DictAccess*, chunk_index: felt, chunk_index_f: felt, element: felt*
    ) -> (word_dict: DictAccess*) {
        if (chunk_index == chunk_index_f) {
            return (word_dict=word_dict,);
        }
        let original_word_dict = word_dict;
        let (value) = dict_read{dict_ptr=word_dict}(chunk_index);
        let word_dict = original_word_dict + 3;
        split_word(value, 16, element);
        return get_aligned(
            word_dict=word_dict,
            chunk_index=chunk_index + 1,
            chunk_index_f=chunk_index_f,
            element=&element[16],
        );
    }

    func split_word{range_check_ptr}(value: felt, len: felt, dst: felt*) {
        if (len == 0) {
            assert value = 0;
            return ();
        }
        let output = &dst[len - 1];
        let base = 256;
        let bound = 256;
        %{
            memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base
            assert res < ids.bound, f'split_int(): Limb {res} is out of range.'
        %}
        tempvar low_part = [output];
        assert_nn_le(low_part, bound - 1);
        return split_word((value - low_part) / 256, len - 1, dst);
    }

    // @notice Expend the memory with length bytes
    // @param self - The pointer to the memory.
    // @param length - The number of bytes to add.
    // @return The new pointer to the memory.
    // @return The gas cost of this expansion.
    func expand{range_check_ptr}(self: model.Memory*, length: felt) -> (
        new_memory: model.Memory*, cost: felt
    ) {
        let (last_memory_size_word, _) = unsigned_div_rem(value=self.bytes_len + 31, div=32);
        let (last_memory_cost, _) = unsigned_div_rem(
            value=last_memory_size_word * last_memory_size_word, div=512
        );
        let last_memory_cost = last_memory_cost + (3 * last_memory_size_word);

        tempvar new_bytes_len = self.bytes_len + length;
        let (new_memory_size_word, _) = unsigned_div_rem(value=new_bytes_len + 31, div=32);
        let (new_memory_cost, _) = unsigned_div_rem(
            value=new_memory_size_word * new_memory_size_word, div=512
        );
        let new_memory_cost = new_memory_cost + (3 * new_memory_size_word);

        let cost = new_memory_cost - last_memory_cost;

        return (
            new model.Memory(
            word_dict_start=self.word_dict_start,
            word_dict=self.word_dict,
            bytes_len=new_bytes_len,
            ),
            cost,
        );
    }

    // @notice Ensure that the memory as at least length bytes. Expand if necessary.
    // @param self - The pointer to the memory.
    // @param offset - The number of bytes to add.
    // @return The new pointer to the memory.
    // @return The gas cost of this expansion.
    func ensure_length{range_check_ptr}(self: model.Memory*, length: felt) -> (
        new_memory: model.Memory*, cost: felt
    ) {
        let is_memory_expanding = is_le(self.bytes_len + 1, length);
        if (is_memory_expanding != 0) {
            let (new_memory, cost) = Memory.expand(self=self, length=length - self.bytes_len);
            return (new_memory, cost);
        } else {
            return (new_memory=self, cost=0);
        }
    }
}
