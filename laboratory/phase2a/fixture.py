"""Synthetic TLS/canary servers in a Docker --network none namespace only."""

import asyncio
import ssl
from pathlib import Path

V4 = "93.184.216.10"
V6 = "2606:4700:ffff::10"


async def https(reader, writer):
    try:
        request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
        path = request.split(b" ")[1]
        if b"Host: control.example.net\r\n" not in request:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        elif path == b"/redirect":
            writer.write(
                b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
        elif path == b"/huge":
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n")
        elif path == b"/slow":
            await asyncio.sleep(10)
        elif path == b"/header-flood":
            writer.write(b"HTTP/1.1 200 OK\r\nX-Flood: " + b"x" * 20000 + b"\r\n\r\n")
        elif path == b"/chunked":
            writer.write(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"
            )
        else:
            body = Path("/tmp/proof").read_bytes()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
        await writer.drain()
    except (Exception, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def canary(reader, writer):
    # No traffic should ever reach these deliberately listening local canaries.
    with Path("/tmp/canary-hits").open("ab") as log:
        log.write(b"hit\n")
    writer.close()


class DNSCanary(asyncio.DatagramProtocol):
    def datagram_received(self, data, address):
        with Path("/tmp/canary-hits").open("ab") as log:
            log.write(b"udp-hit\n")


async def main():
    servers = []

    def record_sni(sock, name, context):
        Path("/tmp/sni").write_text(name or "")

    for host, certificate in [
        (V4, "server.pem"),
        (V6, "server.pem"),
        ("93.184.216.11", "expired.pem"),
    ]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/lab/certs/" + certificate, "/lab/certs/server.key")
        # Record SNI without logging requests, proof tokens or response bodies.
        context.set_servername_callback(record_sni)
        servers.append(await asyncio.start_server(https, host, 443, ssl=context))
    for host, port in [
        ("127.0.0.1", 5432),
        ("::1", 5432),
        ("10.77.0.10", 5432),
        ("169.254.169.254", 80),
        (V4, 80),
    ]:
        servers.append(await asyncio.start_server(canary, host, port))
    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        DNSCanary, local_addr=("127.0.0.11", 53)
    )
    servers.append(udp)
    Path("/tmp/ready").write_text("ready")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
