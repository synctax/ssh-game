#+feature dynamic-literals

package main

import "core:fmt"
import "core:mem"
import "core:strings"

algorithm_registry := map[string]Registry_Entry {
	DIFFIE_HELLMAN_NAME = Registry_Entry {
		constructor = diffie_hellman_create,
		base_type = KEX_Algorithm,
	},
}

Algorithm_Constructor :: proc(_: mem.Allocator) -> (instance: rawptr, err: _Alloc_Err)

@(private)
_Alloc_Err :: mem.Allocator_Error

Registry_Entry :: struct {
	constructor: Algorithm_Constructor,
	base_type:   typeid,
}

Algorithm_Create_Error :: enum {
	TYPE_MISMATCH,
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

// Sort of gross to return rawptr here but Odin doesnt like closures
diffie_hellman_create :: proc(allocator: mem.Allocator) -> (dh: rawptr, err: _Alloc_Err) {

	create_key_exchange :: proc(t: ^KEX_Algorithm) -> []u8 {
		this := transmute(^Diffie_Hellman)t
		fmt.println("we dispatchin")
		return nil
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

	_dh, alloc_err := new(Diffie_Hellman, allocator)
	if alloc_err != .None {
		return nil, alloc_err
	}

	_dh.name = DIFFIE_HELLMAN_NAME
	_dh.create_key_exchange = create_key_exchange
	_dh.decrypt_key_exchange = decrypt_key_exchange
	_dh.compute_hash = compute_hash
	_dh.destroy = destroy

	return (rawptr)(_dh), nil
}

create_algorithm :: proc(
	$T: typeid,
	name: string,
	allocator := context.allocator,
) -> (
	instance: ^T,
	err: Algorithm_Create_Error,
) {

	if strings.compare("none", name) == 0 {
		return nil, nil
	}

	entry, exists := algorithm_registry[name]
	if !exists {
		fmt.printfln("No matching algorithm '%s' in registry", name)
		return nil, .NAME_NOT_FOUND
	}

	if entry.base_type != T {
		fmt.printfln(
			"Algorithm type in registry did not match request. In registry: '%s'. Expected: '%s'",
			entry.base_type,
			typeid_of(T),
		)
		return nil, .TYPE_MISMATCH
	}

	raw_instance, con_err := entry.constructor(allocator)
	if raw_instance == nil || con_err != .None {
		fmt.printfln("Failed to allocate algorithm with name: %s. Error: %s", name, con_err)
		return nil, .FAILED_TO_ALLOCATE
	}

	algorithm := (^T)(raw_instance)
	return algorithm, nil
}
