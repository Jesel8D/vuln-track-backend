"""Controlled routed TLS/DNS/canaries. No forwarding or external requests."""

import asyncio
import json
import ssl
from pathlib import Path

import dns.message
import dns.rcode
import dns.rrset

STATS = {
    "tls_started": 0,
    "slow_active": 0,
    "slow_closed": 0,
    "canary_hits": 0,
    "dns_queries": 0,
    "sni_valid": 0,
    "host_valid": 0,
}
CONFIG = {}


def save():
    p = Path("/tmp/phase2c-stats.tmp")
    p.write_text(json.dumps(STATS))
    p.replace("/tmp/phase2c-stats.json")


async def canary(reader, writer):
    STATS["canary_hits"] += 1
    save()
    await reader.read(1)
    writer.close()


class UDPCanary(asyncio.DatagramProtocol):
    def datagram_received(self, data, address):
        STATS["canary_hits"] += 1
        save()


async def https(reader, writer):
    STATS["tls_started"] += 1
    save()
    try:
        async with asyncio.timeout(7):
            header = await reader.readuntil(b"\r\n\r\n")
            if b"Host: control.example.net\r\n" in header or b"Host: v6.example.net\r\n" in header:
                STATS["host_valid"] += 1
            else:
                raise ValueError("Host mismatch")
            save()
            path = header.split(b" ")[1]
            if path == b"/slow":
                STATS["slow_active"] += 1
                save()
                try:
                    await reader.read(1)  # Observe actual gateway socket closure, not a mock.
                finally:
                    STATS["slow_active"] -= 1
                    STATS["slow_closed"] += 1
                    save()
                return
            if path == b"/redirect":
                writer.write(
                    b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            else:
                body = b"VulnTrack controlled Phase 2C fixture only\n"
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + body
                )
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def dns_server(reader, writer):
    try:
        async with asyncio.timeout(1):
            length = int.from_bytes(await reader.readexactly(2), "big")
            if not 12 <= length <= 512:
                return
            query = dns.message.from_wire(await reader.readexactly(length))
            STATS["dns_queries"] += 1
            save()
            name = query.question[0].name.to_text(omit_final_dot=True)
            kind = query.question[0].rdtype
            response = dns.message.make_response(query)
            mode_file = Path("/tmp/phase2c-dns-mode.json")
            mode = json.loads(mode_file.read_text()) if mode_file.exists() else "normal"
            if name == "fail.example.net" or mode == "fail":
                response.set_rcode(dns.rcode.SERVFAIL)
            elif kind == 1 and name != "v6.example.net":
                if name == "rebind.example.net":
                    STATS["rebind_a"] = STATS.get("rebind_a", 0) + 1
                    address = CONFIG["target4"] if STATS["rebind_a"] == 1 else CONFIG["forbidden4"]
                else:
                    address = CONFIG["other4"] if mode == "changed" else CONFIG["target4"]
                response.answer.append(dns.rrset.from_text(name + ".", 0, "IN", "A", address))
            elif kind == 28 and name == "v6.example.net":
                response.answer.append(
                    dns.rrset.from_text(name + ".", 0, "IN", "AAAA", CONFIG["target6"])
                )
            wire = response.to_wire()
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def main():
    global CONFIG
    CONFIG = json.loads(Path("/tmp/phase2c-config.json").read_text())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/lab/certs/server.pem", "/lab/certs/server.key")

    def sni(sock, name, ctx):
        if name in ("control.example.net", "v6.example.net"):
            STATS["sni_valid"] += 1
            save()

    context.set_servername_callback(sni)
    servers = []
    for ip in (CONFIG["target4"], CONFIG["other4"], CONFIG["target6"], CONFIG["other6"]):
        servers.append(await asyncio.start_server(https, ip, 443, ssl=context))
    for ip in CONFIG["dns_bind"]:
        servers.append(await asyncio.start_server(dns_server, ip, 53))
    for ip, ports in CONFIG["canaries"].items():
        for port in ports:
            servers.append(await asyncio.start_server(canary, ip, port))
        await asyncio.get_running_loop().create_datagram_endpoint(UDPCanary, local_addr=(ip, 53))
    save()
    Path("/tmp/phase2c-ready.json").write_text("{}")
    async with servers[0]:
        await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
