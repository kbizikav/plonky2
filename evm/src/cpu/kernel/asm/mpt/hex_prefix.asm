// Computes the RLP encoding of the hex-prefix encoding of the given nibble list
// and termination flag. Writes the result to @SEGMENT_RLP_RAW starting at the
// given position, and returns the updated position, i.e. a pointer to the next
// unused offset.
//
// Pre stack: rlp_start_pos, num_nibbles, packed_nibbles, terminated, retdest
// Post stack: rlp_end_pos
global hex_prefix_rlp:
    DUP2 %assert_lt_const(65)
    
    PUSH 2 DUP3 DIV 
    // Compute the length of the hex-prefix string, in bytes:
    // hp_len = num_nibbles / 2 + 1 = i + 1
    %increment
    // stack: hp_len, rlp_pos, num_nibbles, packed_nibbles, terminated, retdest

    // Write the RLP header.
    DUP1 %gt_const(55) %jumpi(rlp_header_large)
    DUP1 %gt_const(1) %jumpi(rlp_header_medium)

    // The hex-prefix is a single byte. It must be <= 127, since its first
    // nibble only has two bits. So this is the "small" RLP string case, where
    // the byte is its own RLP encoding.
    // stack: hp_len, rlp_pos, num_nibbles, packed_nibbles, terminated, retdest
    POP
first_byte:
    // stack: rlp_pos, num_nibbles, packed_nibbles, terminated, retdest
    // get the first nibble, if num_nibbles is odd, or zero otherwise
    SWAP2
    // stack: packed_nibbles, num_nibbbles, rlp_pos, terminated, retdest
    DUP2 DUP1
    %mod_const(2)
    // stack: parity, num_nibbles, packed_nibbles, num_nibbles, rlp_pos, terminated, retdest
    SWAP1 SUB
    %mul_const(4)
    SHR
    // stack: first_nibble_or_zero, num_nibbles, rlp_pos, terminated, retdest
    SWAP2
    // stack: rlp_pos, num_nibbles, first_nibble_or_zero, terminated, retdest
    SWAP3
    // stack: terminated, num_nibbles, first_nibble_or_zero, rlp_pos, retdest
    %mul_const(2)
    // stack: terminated * 2, num_nibbles, first_nibble_or_zero, rlp_pos, retdest
    SWAP1
    // stack: num_nibbles, terminated * 2, first_nibble_or_zero, rlp_pos, retdest
    %mod_const(2) // parity
    ADD
    // stack: parity + terminated * 2, first_nibble_or_zero, rlp_pos, retdest
    %mul_const(16)
    ADD
    // stack: first_byte, rlp_pos, retdest
    DUP2
    %mstore_rlp
    %increment
    // stack: rlp_pos', retdest
    SWAP1
    JUMP
    
remaining_bytes:
    // stack: rlp_pos, num_nibbles, packed_nibbles, retdest
    SWAP2
    PUSH @U256_MAX
    // stack: U256_MAX, packed_nibbles, num_nibbles, rlp_pos, ret_dest
    SWAP1 SWAP2 DUP1
    %mod_const(2)
    // stack: parity, num_nibbles, U256_MAX, packed_nibbles, rlp_pos, ret_dest
    SWAP1 SUB DUP1
    // stack: num_nibbles - parity, num_nibbles - parity, U256_MAX, packed_nibbles, rlp_pos, ret_dest
    %div_const(2)
    // stack: remaining_bytes, num_nibbles - parity, U256_MAX, packed_nibbles, rlp_pos, ret_dest
    SWAP2 SWAP1
    // stack: num_nibbles - parity, U256_MAX, remaining_bytes, packed_nibbles, rlp_pos, ret_dest
    %mul_const(4)
    // stack: 4*(num_nibbles - parity), U256_MAX, remaining_bytes, packed_nibbles, rlp_pos, ret_dest
    PUSH 256 SUB
    // stack: 256 - 4*(num_nibbles - parity), U256_MAX, remaining_bytes, packed_nibbles, rlp_pos, ret_dest
    SHR
    // stack: mask, remaining_bytes, packed_nibbles, rlp_pos, ret_dest
    SWAP1 SWAP2
    AND
    %stack
        (remaining_nibbles, remaining_bytes, rlp_pos) ->
        (rlp_pos, remaining_nibbles, remaining_bytes)
    %mstore_unpacking_rlp
    SWAP1
    JUMP


rlp_header_medium:
    // stack: hp_len, rlp_pos, num_nibbles, packed_nibbles, terminated, retdest
    %add_const(0x80) // value = 0x80 + hp_len
    DUP2 // offset = rlp_pos
    %mstore_rlp
    // stack: rlp_pos, num_nibbles, packed_nibbles, terminated, retdest
    // rlp_pos += 1
    %increment

    %stack
        (rlp_pos, num_nibbles, packed_nibbles, terminated, retdest) ->
        (rlp_pos, num_nibbles, packed_nibbles, terminated, remaining_bytes, num_nibbles, packed_nibbles, retdest)

    %jump(first_byte)

rlp_header_large:
    // stack: hp_len, rlp_pos, num_nibbles, packed_nibbles, terminated, retdest
    // In practice hex-prefix length will never exceed 256, so the length of the
    // length will always be 1 byte in this case.

    PUSH 0xb8 // value = 0xb7 + len_of_len = 0xb8
    DUP3 // offset = rlp_pos
    %mstore_rlp

    // stack: hp_len, rlp_pos, num_nibbles, packed_nibbles, terminated, retdest
    DUP2 %increment // offset = rlp_pos + 1
    %mstore_rlp

    // stack: rlp_pos, num_nibbles, packed_nibbles, terminated, retdest
    // rlp_pos += 2
    %add_const(2)

    %stack
        (rlp_pos, num_nibbles, packed_nibbles, terminated, retdest) ->
        (rlp_pos, num_nibbles, packed_nibbles, terminated, remaining_bytes, num_nibbles, packed_nibbles, retdest)

    %jump(first_byte)

