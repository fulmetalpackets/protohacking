# Global constants.
COMPRESSED_FILE = 'stuff.gz'
CLIENT_IFACE = 'docker0'
TCP_PORT = 1234
UDP_PORT = 4321
LONG_SLEEP_DUR = 1.0
SHORT_SLEEP_DUR = 0.2
DOCKER_TIMEOUT = 30
DOCKER_NAME = 'pcap_server'
OUTPUT_FILE = 'server_output.txt'

if __name__ == '__main__':
    import argparse
    import docker
    import os
    import requests
    import signal
    import socket
    import sys
    import time

    # Add repo's root directory to path so we can import from protocols/.
    parent_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(parent_dir)
    sys.path.insert(0, root_dir)

    from datetime import datetime
    from protocols.fake_proto import *
    from scapy.all import *

    # Parse command line arguments.
    parser = argparse.ArgumentParser('Generate fake_proto traffic between a '
                                     'client and server.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='display contents of packets sent/received')
    parser.add_argument('-r', '--repeat', action='store_true',
                        help='continue sending traffic to server until Ctrl+C')
    parser.add_argument('-b', '--build', action='store_true',
                        help='rebuild the Docker container for the server')
    parser.add_argument('-o', '--output', type=argparse.FileType('wb'),
                        default=OUTPUT_FILE,
                        help=(f'File where the server output will be written '
                              f'to. Default is {OUTPUT_FILE}.'))
    args = parser.parse_args()

    client_ip = get_if_addr(CLIENT_IFACE)
    open_sockets = []
    container = None
    create_container = False
    remove_container = False

    # Build the Docker container if the image doesn't exist or -b is specified.
    docker_client = docker.from_env()
    try:
        docker_client.images.get(DOCKER_NAME)
        print(f'Docker image for {DOCKER_NAME} found.')
    except docker.errors.ImageNotFound:
        print(f'Could not find Docker image for {DOCKER_NAME}.')
        args.build = True
    if args.build:
        print(f'Building {DOCKER_NAME} image...')
        docker_client.images.build(path=root_dir, tag=DOCKER_NAME)
        create_container = True

    # Check if the container exists and, if so, check its current state.
    start_time = datetime.now()
    try:
        container = docker_client.containers.get(DOCKER_NAME)
        print(f'Docker container for {DOCKER_NAME} found.')
        remove_container = True
        if not create_container:
            if container.status == 'running':
                print(f'Docker container is already running.')
            elif container.status == 'restarting':
                print(f'Docker container is restarting. Waiting...')
                time.sleep(5)
            elif container.status == 'paused':
                print(f'Docker container is paused. Unpausing...')
                container.unpause()
            elif container.status in ['created', 'exited']:
                print(f'Docker container is not running. Starting...')
                container.start()
            else:
                print(f'Docker container in unexpected state. Recreating...')
                create_container = True
    except docker.errors.NotFound:
        print(f'Could not find Docker container for {DOCKER_NAME}.')
        create_container = True
        remove_container = False

    # Create the container, first removing any existing containers.
    if create_container:
        if remove_container:
            print(f'Attempting to remove existing {DOCKER_NAME} container...')
            try:
                docker_client.containers.get(DOCKER_NAME).remove(force=True)
                print('Existing container removed.')
            except:
                print('Could not remove existing container.')
        print(f'Creating and running Docker container for {DOCKER_NAME}...')
        # container = docker_client.containers.run(DOCKER_NAME, name=DOCKER_NAME,
        #                                          auto_remove=True, detach=True)
        os.system(f'docker run --rm -d --name {DOCKER_NAME} {DOCKER_NAME}')
        container = docker_client.containers.get(DOCKER_NAME)
        time.sleep(LONG_SLEEP_DUR)  # Give server time to open TCP socket.

    # Wait for the container to start.
    if container.status != 'running':
        timeout = time.time() + DOCKER_TIMEOUT
        print('Waiting for Docker container to start.', end='')
        sys.stdout.flush()
        while container.status != 'running':
            if time.time() > timeout:
                sys.exit(f'\nERR: failed to start Docker container. '
                         f'Try starting it manually via docker run --rm -d '
                         f'--name {DOCKER_NAME} {DOCKER_NAME}')
            time.sleep(3)
            print('.', end='')
            sys.stdout.flush()
            container.reload()
        print()

    # Get server's IP address.
    server_ip = container.attrs['NetworkSettings']['IPAddress']

    # Close all open sockets.
    def clean_up(output_file):
        print('\nClosing sockets...')
        for socket in list(open_sockets):
            try:
                socket.close()
            except:
                pass
            finally:
                open_sockets.remove(socket)
        print('Sockets closed.')
        print(f'Writing server output to {output_file.name}...')
        with output_file as file:
            file.write(container.logs(since=start_time))
        print(f'Output saved.')

    # Signal handler calls clean_up() before exiting.
    def signal_handler(sig, frame):
        clean_up(args.output)
        sys.exit(0)

    # Register our signal handler to execute when SIG_INT is received (Ctrl+C).
    signal.signal(signal.SIGINT, signal_handler)

    # Create UDP socket.
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    open_sockets.append(udp_socket)
    client_udp_address = (client_ip, UDP_PORT)
    print(f'Starting up UDP port on: {client_udp_address}')
    udp_socket.bind(client_udp_address)

    # Create TCP StreamSocket.
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    open_sockets.append(tcp_socket)
    server_tcp_address = (server_ip, TCP_PORT)
    print(f'Connecting to TCP port at: {server_tcp_address}')
    tcp_socket.connect(server_tcp_address)
    ss = StreamSocket(tcp_socket, Raw)
    open_sockets.append(ss)
    time.sleep(LONG_SLEEP_DUR) # Wait for "waiting for data...." message.

    while True:
        session_id = os.urandom(5)
        hb_int = 0
        pkt_sent = 0
        gcount = 0

        # First packet - request.
        request = Header(ipaddress=client_ip)/Request(sessionId=session_id)
        if args.verbose:
            print('Sending the following request packet via TCP:')
            request.show()
        response_pkt = ss.sr1(request)
        if args.verbose:
            print('Received the following response packet via TCP:')
            response_pkt.show()
        if response_pkt.load[4:6] == b'\x00\x02': # Response packet identifier.
            hb_int = int.from_bytes(response_pkt.load[-2:], byteorder='big')
        else:
            sys.exit('ERR: wrong packet type sent')

        # Create and send heartbeat packet.
        resp = requests.get('https://api.3geonames.org/?randomland=yes&json=1')
        resp_json = resp.json()
        geo = f'{resp_json["major"]["latt"]},{resp_json["major"]["longt"]}'
        hb_pkt = (IP(dst=server_ip)
                  /UDP(sport=UDP_PORT, dport=UDP_PORT)
                  /Header(ipaddress=client_ip, message_type=3)
                  /Heartbeat(count=gcount, sessionId=session_id, geo=geo))
        if args.verbose:
            print('Sending the following heartbeat packet via UDP:')
            hb_pkt.show()
        send(hb_pkt)
        time.sleep(SHORT_SLEEP_DUR)  # Allow for sockets to settle.
        gcount += 1

        # Read 'stuff' from a file and break into chunks.
        with open(os.path.join(parent_dir, COMPRESSED_FILE), mode='rb') as file:
            stuff = file.read()
        chunks, chunk_size = len(stuff), 100
        l_stuff = [stuff[i:i+chunk_size] for i in range(0, chunks, chunk_size)]
        data_remaining = len(l_stuff) - 1 # Account for 0 math.
        for item in l_stuff:

            # Check if we need to send heartbeat packet.
            if pkt_sent != 0 and pkt_sent % hb_int == 0:
                hb_pkt[Heartbeat].count = gcount
                gcount += 1
                if args.verbose:
                    print('Sending the following heartbeat packet via UDP:')
                    hb_pkt.show()
                send(hb_pkt)
                pkt_sent = 0

            # Send data.
            data_pkt = (Header(ipaddress=client_ip, message_type=4)
                        /Data(remaining=data_remaining, data=item))
            if args.verbose:
                print('Sending the following data packet via TCP:')
                data_pkt.show()
            ss.send(data_pkt)
            time.sleep(SHORT_SLEEP_DUR)
            data_remaining -= 1
            pkt_sent += 1
        time.sleep(LONG_SLEEP_DUR) # Wait for last packet.
        print('Finished transaction.')
        if not args.repeat:
            break
    clean_up(args.output)