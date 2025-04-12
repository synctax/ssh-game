package main

import "core:fmt"
import "core:mem"

Algorithm_Create_Error :: enum {
	NAME_NOT_FOUND,
	FAILED_TO_ALLOCATE,
}

Algorithm :: struct {
	name: string,
}

KEX_Algorithm :: struct {
	using _:              Algorithm,
	create_key_exchange:  proc(this: ^KEX_Algorithm) -> []u8,
	decrypt_key_exchange: proc(this: ^KEX_Algorithm, ex: []u8) -> []u8,
	compute_hash:         proc(this: ^KEX_Algorithm, value: []u8) -> []u8,
}

DIFFIE_HELLMAN_NAME :: "diffie-hellman-group14-sha256"
Diffie_Hellman :: struct {
	using _: KEX_Algorithm,
}

diffie_hellman_create :: proc(
	allocator := context.allocator,
) -> (
	dh: ^Diffie_Hellman,
	err: mem.Allocator_Error,
) #optional_allocator_error {

	create_key_exchange :: proc(this: ^KEX_Algorithm) -> []u8 {
		return make_slice([]u8, 0)
	}

	decrypt_key_exchange :: proc(this: ^KEX_Algorithm, ex: []u8) -> []u8 {
		return make_slice([]u8, 0)
	}

	compute_hash :: proc(this: ^KEX_Algorithm, val: []u8) -> []u8 {
		return make_slice([]u8, 0)
	}

	alloc_err: mem.Allocator_Error
	dh, alloc_err = new(Diffie_Hellman, allocator)
	if alloc_err != nil {
		return nil, alloc_err
	}

	dh.name = DIFFIE_HELLMAN_NAME
	dh.create_key_exchange = create_key_exchange
	dh.decrypt_key_exchange = decrypt_key_exchange
	dh.compute_hash = compute_hash

	return dh, nil
}

create_kex_algorithm :: proc(
	name: string,
	allocator := context.allocator,
) -> (
	algo: ^KEX_Algorithm,
	err: Algorithm_Create_Error,
) {
	switch name {
	case DIFFIE_HELLMAN_NAME:
		algo, err =
			diffie_hellman_create(allocator) or_else nil, Algorithm_Create_Error.FAILED_TO_ALLOCATE
	}

	return algo, err
}
