package main

import "core:fmt"
import "core:mem"

Algorithm_Create_Error :: enum {
	NAME_NOT_FOUND,
	FAILED_TO_ALLOCATE,
}

Algorithm :: struct {
	name:    string,
	destroy: proc(this: ^Algorithm),
}

KEX_Algorithm :: struct {
	using _:              Algorithm,
	create_key_exchange:  proc(this: ^KEX_Algorithm) -> []u8,
	decrypt_key_exchange: proc(this: ^KEX_Algorithm, ex: []u8) -> []u8,
	compute_hash:         proc(this: ^KEX_Algorithm, value: []u8) -> []u8,
}

Host_Key_Algorithm :: struct {
	using _:                     Algorithm,
	import_key:                  proc(this: ^Host_Key_Algorithm),
	create_key_and_certificates: proc(this: ^Host_Key_Algorithm) -> []u8,
	create_signature_data:       proc(this: ^Host_Key_Algorithm, hash: []u8) -> []u8,
}

Cipher_Algorithm :: struct {
	using _:    Algorithm,
	block_size: u32,
	key_size:   u32,
	encrypt:    proc(this: ^Cipher_Algorithm, data: []u8) -> u8,
	decrypt:    proc(this: ^Cipher_Algorithm, data: []u8) -> u8,
}

MAC_Algorithm :: struct {
	using _:       Algorithm,
	keysize:       u32,
	digest_length: u32,
	set_key:       proc(this: ^MAC_Algorithm, key: []u8),
	compute_hash:  proc(this: ^MAC_Algorithm, data: []u8) -> []u8,
}

Compression_Algorithm :: struct {
	using _:    Algorithm,
	compress:   proc(this: Compression_Algorithm, data: []u8) -> []u8,
	decompress: proc(this: Compression_Algorithm, data: []u8) -> []u8,
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

	destroy :: proc(using this: ^Algorithm) {
		free(this)
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
	dh.destroy = destroy

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

create_host_key_algorithm :: proc(
	name: string,
	allocator := context.allocator,
) -> (
	algo: ^Host_Key_Algorithm,
	err: Algorithm_Create_Error,
) {
	switch name {
	case "none":
		algo, err = nil, nil
	case:
		algo, err = nil, Algorithm_Create_Error.NAME_NOT_FOUND
	}

	return algo, err
}

create_cipher_algorithm :: proc(
	name: string,
	allocator := context.allocator,
) -> (
	algo: ^Cipher_Algorithm,
	err: Algorithm_Create_Error,
) {
	switch name {
	case "none":
		algo, err = nil, nil
	case:
		algo, err = nil, Algorithm_Create_Error.NAME_NOT_FOUND
	}

	return algo, err
}

create_mac_algorithm :: proc(
	name: string,
	allocator := context.allocator,
) -> (
	algo: ^MAC_Algorithm,
	err: Algorithm_Create_Error,
) {
	switch name {
	case "none":
		algo, err = nil, nil
	case:
		algo, err = nil, Algorithm_Create_Error.NAME_NOT_FOUND
	}

	return algo, err
}

create_compression_algorithm :: proc(
	name: string,
	allocator := context.allocator,
) -> (
	algo: ^Compression_Algorithm,
	err: Algorithm_Create_Error,
) {
	switch name {
	case "none":
		algo, err = nil, nil
	case:
		algo, err = nil, Algorithm_Create_Error.NAME_NOT_FOUND
	}

	return algo, err
}
