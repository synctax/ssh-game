package main

import "core:fmt"
import "core:mem"
import "core:net"

main :: proc() {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	context.allocator = mem.tracking_allocator(&track)

	endpoint := net.Endpoint {
		port    = 22,
		address = net.IP4_Loopback,
	}


	socket, listenerr := net.listen_tcp(endpoint)
	if listenerr != nil {
		fmt.panicf("Failed to initialise listener: %s", listenerr)
	}

	client, endp, accepterr := net.accept_tcp(socket)

	err := ssh_handle_connection(client)

	if len(track.allocation_map) > 0 {
		for _, entry in track.allocation_map {
			fmt.eprintf("%v allocated %v bytes\n", entry.location, entry.size)
		}
	}
}
