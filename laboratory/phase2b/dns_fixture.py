"""Owned TCP DNS fixtures; no forwarding, recursion or external DNS queries."""

import asyncio
from pathlib import Path

import dns.flags
import dns.message
import dns.rdatatype
import dns.rrset

queries = 0
rebind_a = 0


async def serve(reader, writer):
    global queries, rebind_a
    try:
        length = int.from_bytes(await reader.readexactly(2), "big")
        if not 12 <= length <= 512:
            return
        question = dns.message.from_wire(await reader.readexactly(length))
        queries += 1
        Path("/tmp/dns-count").write_text(str(queries))
        name = question.question[0].name.to_text(omit_final_dot=True)
        kind = dns.rdatatype.to_text(question.question[0].rdtype)
        if name == "slow.example.net":
            await asyncio.sleep(10)
            return
        if name == "oversize.example.net":
            writer.write((8192).to_bytes(2, "big"))
            await writer.drain()
            return
        response = dns.message.make_response(question)
        records = []
        value = "93.184.216.10" if kind == "A" else "2606:4700:ffff::10"
        if name == "rebind.example.net" and kind == "A":
            rebind_a += 1
            value = "93.184.216.10" if rebind_a == 1 else "93.184.216.12"
        if name == "mixed.example.net":
            records = [(name, "A", ["93.184.216.10", "10.77.0.10"])]
        elif name == "loop.example.net":
            records = [
                (name, "CNAME", ["other.example.net."]),
                ("other.example.net", "CNAME", [name + "."]),
            ]
        elif name == "cname.example.net":
            records = [
                (name, "CNAME", ["control.example.net."]),
                ("control.example.net", kind, [value]),
            ]
        else:
            records = [(name, kind, [value])]
        if name == "truncated.example.net":
            response.flags |= dns.flags.TC
        for owner, record_kind, values in records:
            response.answer.append(dns.rrset.from_text(owner + ".", 0, "IN", record_kind, *values))
        wire = response.to_wire()
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()
    except asyncio.CancelledError:
        pass
    except Exception as error:
        Path("/tmp/dns-failure").write_text(type(error).__name__)
    finally:
        writer.close()


async def start(canary):
    return [
        await asyncio.start_server(serve, "10.77.0.53", 53),
        await asyncio.start_server(serve, "fd00:77::53", 53),
        await asyncio.start_server(canary, "93.184.216.12", 443),
    ]
