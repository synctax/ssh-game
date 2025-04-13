package main

import "core:encoding/endian"
import "core:fmt"
import "core:math/rand"
import "core:net"
import "core:strings"

MAX_PACKET_SIZE :: 35000
COOKIE_SIZE :: 16

SERVER_PROTO_VERSION_STRING: string : "SSH-2.0-billsSSH_3.6.3q3"

SUPPORTED_KEX_ALGORITHMS :: []string{DIFFIE_HELLMAN_NAME}
SUPPORTED_HOST_KEY_ALGORITHMS :: []string{"rsa-sha2-256"}
SUPPORTED_ENCRYPTION_ALGORITHMS :: []string{"aes128-ctr"}
SUPPORTED_MAC_ALGORITHMS :: []string{"hmac-sha1"}
SUPPORTED_COMP_ALGORITHMS :: []string{"none"}

SSH_Error :: union {
	net.Network_Error,
	SSH_FAILED_HANDSHAKE,
}

SSH_FAILED_HANDSHAKE :: struct {
	step: SSH_State,
}

SSH_State :: enum {
	DISCONNECTED,
	PROTO_VERSION_EXCHANGE,
	KEX_INIT,
}

SSH_Msg_Type :: enum u8 {
	UNKNOWN                 = 0,
	SSH_MSG_DISCONNECT      = 1,
	SSH_MSG_IGNORE          = 2,
	SSH_MSG_UNIMPLEMENTED   = 3,
	SSH_MSG_DEBUG           = 4,
	SSH_MSG_SERVICE_REQUEST = 5,
	SSH_MSG_SERVICE_ACCEPT  = 6,
	SSH_MSG_KEXINIT         = 20,
	SSH_MSG_NEWKEYS         = 21,
}

SSH_Connection_State :: struct {
	socket:                net.TCP_Socket,
	state:                 SSH_State,
	read_buffer:           [MAX_PACKET_SIZE]u8,
	write_buffer:          [MAX_PACKET_SIZE]u8,
	kex_algorithm:         ^KEX_Algorithm,
	host_key_algorithm:    ^Host_Key_Algorithm,
	encryption_algorithm:  ^Cipher_Algorithm,
	mac_algorithm:         ^MAC_Algorithm,
	compression_algorithm: ^Compression_Algorithm,
}

connection_state_clear_algorithms :: proc(using conn_state: ^SSH_Connection_State) {
	// TODO: most of these are required and should not be null, but we must check while impl is in progress
	if kex_algorithm != nil {kex_algorithm->destroy()}
	if host_key_algorithm != nil {host_key_algorithm->destroy()}
	if encryption_algorithm != nil {encryption_algorithm->destroy()}
	if mac_algorithm != nil {mac_algorithm->destroy()}
	if compression_algorithm != nil {compression_algorithm->destroy()}
}

SSH_Algo_List :: struct {
	kex:             []string,
	host_key:        []string,
	encryption_cts:  []string,
	encryption_stc:  []string,
	mac_cts:         []string,
	mac_stc:         []string,
	compression_cts: []string,
	compression_stc: []string,
}

algo_list_clear :: proc(using list: ^SSH_Algo_List) {
	delete(kex)
	delete(host_key)
	delete(encryption_cts)
	delete(encryption_stc)
	delete(mac_cts)
	delete(mac_stc)
	delete(compression_cts)
	delete(compression_stc)
}

@(private)
_write_u32 :: #force_inline proc(b: []u8, offset: int, val: u32) -> (new_offset: int) {
	endian.put_u32(b[offset:], .Big, val)
	return offset + 4
}

@(private)
_read_u32 :: #force_inline proc(b: []u8, offset: int) -> (out: u32, new_offset: int, ok: bool) {
	out = endian.get_u32(b[offset:offset + 4], .Big) or_return
	return out, offset + 4, true
}

@(private)
_write_string :: proc(b: []u8, offset: int, s: string) -> (new_offset: int) {
	length := cast(u32)len(s)
	off := _write_u32(b, offset, length)
	copy(b[off:], transmute([]u8)s)
	return off + cast(int)length
}

@(private)
_write_name_list :: proc(b: []u8, offset: int, list: []string) -> (new_offset: int) {
	name_list := strings.join(list, ",")
	defer delete(name_list)
	return _write_string(b, offset, name_list)
}

@(private)
_read_name_list :: proc(b: []u8, offset: int) -> (list: []string, new_offset: int, ok: bool) {
	length, off, success := _read_u32(b, offset)
	if len(b) < int(length) + 4 {
		return nil, 0, false
	}
	list_string := transmute(string)b[off:off + int(length)]
	list = strings.split(list_string, ",")

	return list, offset + int(length) + 4, true
}

@(private)
_write_packet :: proc(state: ^SSH_Connection_State, payload: []u8) -> (err: net.Network_Error) {
	payload_len := len(payload)
	block_size := 8

	length_before_padding := 5 + payload_len
	padding_len := block_size - (length_before_padding % block_size)
	if padding_len < 4 {
		padding_len += block_size
	}

	buffer := state.write_buffer[:]
	offset := 0

	packet_len := u32(1 + padding_len + payload_len)
	offset = _write_u32(state.write_buffer[:], offset, packet_len)
	state.write_buffer[offset] = cast(u8)padding_len
	offset += 1

	copy(buffer[offset:], payload)
	offset += payload_len

	_ = rand.read(buffer[offset:offset + padding_len])
	offset += padding_len

	_, send_err := net.send_tcp(state.socket, buffer[:offset])
	return send_err
}

@(private)
_read_packet :: proc(
	state: ^SSH_Connection_State,
) -> (
	type: SSH_Msg_Type,
	payload: []byte,
	e: net.Network_Error,
) {
	header: [6]u8
	_, header_err := net.recv_tcp(state.socket, header[:])
	if header_err != nil {
		fmt.printfln("failed to read packet header: %s", header_err)
		return nil, nil, header_err
	}

	// bytes are in network order (big endian)
	packet_size, _ := endian.get_u32(header[:4], .Big)
	padding_size := cast(u32)header[4]
	type = cast(SSH_Msg_Type)header[5]

	_, rest_err := net.recv_tcp(state.socket, state.read_buffer[:packet_size])
	if rest_err != nil {
		fmt.printfln("failed reading packet payload: %s", rest_err)
	}

	payload_size := packet_size - padding_size - 1
	payload = state.read_buffer[:payload_size]

	return type, payload, nil
}

@(private)
_parse_algos :: proc(out: ^SSH_Algo_List, payload: []u8) -> (ok: bool) {
	payload_len := len(payload)
	if payload_len < 21 {
		return false
	}

	right_bound := payload_len - 5
	namelists := payload[16:right_bound]

	off := 0
	out.kex, off = _read_name_list(namelists, off) or_return
	out.host_key, off = _read_name_list(namelists, off) or_return
	out.encryption_cts, off = _read_name_list(namelists, off) or_return
	out.encryption_stc, off = _read_name_list(namelists, off) or_return
	out.mac_cts, off = _read_name_list(namelists, off) or_return
	out.mac_stc, off = _read_name_list(namelists, off) or_return
	out.compression_cts, off = _read_name_list(namelists, off) or_return
	out.compression_stc, off = _read_name_list(namelists, off) or_return

	return true
}

@(private)
_find_consensus :: proc(a: []string, b: []string) -> (found: string, ok: bool) {
	for a_name in a {
		for b_name in b {
			if strings.compare(a_name, b_name) == 0 {
				return a_name, true
			}
		}
	}
	return "", false
}

@(private)
_set_algos :: proc(state: ^SSH_Connection_State, algos: ^SSH_Algo_List) -> (ok: bool) {
	kexname := _find_consensus(SUPPORTED_KEX_ALGORITHMS, algos.kex) or_return
	hostname := _find_consensus(SUPPORTED_HOST_KEY_ALGORITHMS, algos.host_key) or_return
	encryptionname := _find_consensus(
		SUPPORTED_ENCRYPTION_ALGORITHMS,
		algos.encryption_cts,
	) or_return
	macname := _find_consensus(SUPPORTED_MAC_ALGORITHMS, algos.mac_cts) or_return
	compname := _find_consensus(SUPPORTED_COMP_ALGORITHMS, algos.compression_cts) or_return

	err: Algorithm_Create_Error
	state.kex_algorithm, err = create_kex_algorithm(kexname)
	state.host_key_algorithm, err = create_host_key_algorithm(hostname)
	state.encryption_algorithm, err = create_cipher_algorithm(encryptionname)
	state.mac_algorithm, err = create_mac_algorithm(macname)
	state.compression_algorithm, err = create_compression_algorithm(compname)

	if err != nil {
		fmt.printfln("failed to construct one or more algorithms: %s", err)
		return false
	}

	return true
}

ssh_handle_connection :: proc(socket: net.TCP_Socket) -> (err: SSH_Error) {
	defer net.close(socket)

	state := SSH_Connection_State {
		socket = socket,
		state  = .PROTO_VERSION_EXCHANGE,
	}
	defer connection_state_clear_algorithms(&state)

	main_loop: for state.state != .DISCONNECTED {
		switch state.state {
		case .PROTO_VERSION_EXCHANGE:
			// send version string
			server_send_line := SERVER_PROTO_VERSION_STRING + "\r\n"
			_, send_err := net.send_tcp(socket, transmute([]u8)server_send_line)
			if send_err != nil {
				err = SSH_FAILED_HANDSHAKE{.PROTO_VERSION_EXCHANGE}
				state.state = .DISCONNECTED
				break
			}

			// recieve version string
			pve_buf: [255]u8
			n, pve_err := net.recv_tcp(socket, pve_buf[:])
			if pve_err != nil {
				fmt.printfln("Failed to recv proto version string: %s", pve_err)
				err = SSH_FAILED_HANDSHAKE{.PROTO_VERSION_EXCHANGE}
				state.state = .DISCONNECTED
				break
			}

			// parse to verify
			pve_msg := string(pve_buf[:n])
			if !strings.starts_with(pve_msg, "SSH-2.0-") {
				err = SSH_FAILED_HANDSHAKE{.PROTO_VERSION_EXCHANGE}
				state.state = .DISCONNECTED
				break
			}
			fmt.print("recvd proto_version_string: ", pve_msg)
			state.state = .KEX_INIT
		case .KEX_INIT:
			//build kex_init payload
			kex_init_payload: [2048]u8
			kex_init_payload[0] = cast(u8)SSH_Msg_Type.SSH_MSG_KEXINIT
			_ = rand.read(kex_init_payload[1:COOKIE_SIZE + 1])
			offset := COOKIE_SIZE + 1

			offset = _write_name_list(kex_init_payload[:], offset, SUPPORTED_KEX_ALGORITHMS)
			offset = _write_name_list(kex_init_payload[:], offset, SUPPORTED_HOST_KEY_ALGORITHMS)
			offset = _write_name_list(kex_init_payload[:], offset, SUPPORTED_ENCRYPTION_ALGORITHMS)
			offset = _write_name_list(kex_init_payload[:], offset, SUPPORTED_ENCRYPTION_ALGORITHMS)
			offset = _write_name_list(kex_init_payload[:], offset, SUPPORTED_MAC_ALGORITHMS)
			offset = _write_name_list(kex_init_payload[:], offset, SUPPORTED_MAC_ALGORITHMS)
			offset = _write_name_list(kex_init_payload[:], offset, SUPPORTED_COMP_ALGORITHMS)
			offset = _write_name_list(kex_init_payload[:], offset, SUPPORTED_COMP_ALGORITHMS)
			offset = _write_name_list(kex_init_payload[:], offset, nil)
			offset = _write_name_list(kex_init_payload[:], offset, nil)

			kex_init_payload[offset] = 0
			offset += 1
			offset = _write_u32(kex_init_payload[:], offset, 0)

			send_err := _write_packet(&state, kex_init_payload[:offset])
			if send_err != nil {
				fmt.printfln("Failed to send packet: %s", send_err)
				err = send_err
				state.state = .DISCONNECTED
				break
			}

			// read packet
			msg_type, payload, read_err := _read_packet(&state)
			if read_err != nil {
				fmt.printfln("Error reading payload: %s", err)
				err = SSH_FAILED_HANDSHAKE{.KEX_INIT}
				state.state = .DISCONNECTED
				break
			}

			// verify msg type as KEX_INIT
			if msg_type != .SSH_MSG_KEXINIT {
				fmt.printfln("Expected KEX_INIT, received: ", msg_type)
				err = SSH_FAILED_HANDSHAKE{.KEX_INIT}
				state.state = .DISCONNECTED
				break
			}
			fmt.println("Recieved kex_init payload: ", transmute(string)payload)
			state.state = .DISCONNECTED
			// TODO: parse KEX_INIT and actually reach concensus

			client_algos: SSH_Algo_List
			defer algo_list_clear(&client_algos)

			parse_ok := _parse_algos(&client_algos, payload)
			if !parse_ok {
				fmt.println("failed to parse client algo list")
			}

			_set_algos(&state, &client_algos)

		case .DISCONNECTED:
			break main_loop
		}
	}


	return err
}
