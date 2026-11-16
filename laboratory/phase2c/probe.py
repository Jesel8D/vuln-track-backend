"""Adversarial worker probes; invoked only through the owned lab runner."""

import asyncio
import json
import os
import resource
import socket
import subprocess
import sys
from pathlib import Path

from laboratory.phase2c.protocol import close, decode, encode, rpc


async def raw_tcp(address, port):
    raw = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    raw.setblocking(False)
    connected = False
    try:
        async with asyncio.timeout(0.3):
            await asyncio.get_running_loop().sock_connect(raw, (address, port))
            connected = True
    except (OSError, TimeoutError):
        pass
    finally:
        raw.close()
    return {"connected": connected}


async def main(request):
    action = request["action"]
    if action == "rpc":
        try:
            return await rpc(
                request["address"], request.get("port", 8443), request["message"], timeout=7
            )
        except (OSError, TimeoutError, EOFError, asyncio.IncompleteReadError, ValueError):
            return {"result": "denied", "code": "GATEWAY_UNAVAILABLE", "transport_closed": True}
    if action == "raw":
        return await asyncio.gather(*(raw_tcp(ip, port) for ip, port in request["targets"]))
    if action == "udp":
        for ip in request["targets"]:
            raw = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM)
            try:
                raw.sendto(b"owned-phase2c-canary", (ip, 53))
            except OSError:
                pass
            finally:
                raw.close()
        return {"sent_probe": True}
    if action == "local":
        hits = []

        async def accept(reader, writer):
            hits.append(True)
            writer.close()

        servers = [await asyncio.start_server(accept, ip, 18080) for ip in ("127.0.0.1", "::1")]
        results = await asyncio.gather(raw_tcp("127.0.0.1", 18080), raw_tcp("::1", 18080))
        for server in servers:
            server.close()
            await server.wait_closed()
        return {"results": results, "hits": len(hits)}
    if action == "double":
        reader, writer = await asyncio.open_connection(request["address"], 8443)
        try:
            writer.write(encode(request["message"]))
            await writer.drain()
            first = decode(await asyncio.wait_for(reader.readuntil(b"\n"), 7))
            try:
                writer.write(encode(request["message"]))
                await writer.drain()
                second = await asyncio.wait_for(reader.read(1), 0.5)
            except (ConnectionError, TimeoutError):
                second = b""
            return {"first": first, "second_response": bool(second)}
        finally:
            await close(writer)
    if action == "security":
        status = Path("/proc/self/status").read_text()
        assert "CapEff:\t0000000000000000" in status and "NoNewPrivs:\t1" in status
        assert not Path("/var/run/docker.sock").exists()
        assert not Path("/tmp/phase2c-config.json").exists()
        assert not Path("/tmp/phase2c-state.json").exists()
        assert os.statvfs("/").f_flag & os.ST_RDONLY
        assert Path("/sys/fs/cgroup/memory.max").read_text().strip() == "134217728"
        assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == "32"
        quota, period = map(int, Path("/sys/fs/cgroup/cpu.max").read_text().split())
        assert quota / period == 0.5 and resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
        try:
            Path("/lab/certs/server.key").read_bytes()
        except PermissionError:
            pass
        else:
            raise AssertionError("Fixture private key accessible to worker")
        assert (
            subprocess.run(
                ["iptables", "-P", "OUTPUT", "ACCEPT"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            != 0
        )
        try:
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            pass
        else:
            raise AssertionError("Raw socket permitted")
        return {
            "capabilities_zero": True,
            "no_new_privileges": True,
            "firewall_mutation_denied": True,
            "raw_socket_denied": True,
            "no_control_or_database_credentials": True,
            "live_readonly_root_and_cgroup_limits": True,
            "fixture_private_key_unreadable": True,
        }
    raise ValueError("Unknown lab probe")


if __name__ == "__main__":
    print(json.dumps(asyncio.run(main(json.load(sys.stdin)))))
