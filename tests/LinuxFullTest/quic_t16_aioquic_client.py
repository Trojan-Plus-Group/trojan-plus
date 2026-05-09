# This script is called by fulltest_quic.py to perform aioquic-based client tests.

import asyncio
import sys
import os
import hashlib
import logging
from aioquic.asyncio import connect as async_connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

logging.basicConfig(level=logging.DEBUG)

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.responses = {} # stream_id -> bytearray
        self.done_events = {} # stream_id -> asyncio.Event

    def quic_event_received(self, event):
        for h3_event in self.h3.handle_event(event):
            if isinstance(h3_event, DataReceived):
                self.responses[h3_event.stream_id] += h3_event.data
            if getattr(h3_event, 'stream_ended', False):
                if h3_event.stream_id in self.done_events:
                    self.done_events[h3_event.stream_id].set()

async def fetch_file(protocol, path):
    stream_id = protocol._quic.get_next_available_stream_id()
    protocol.responses[stream_id] = bytearray()
    protocol.done_events[stream_id] = asyncio.Event()
    
    protocol.h3.send_headers(
        stream_id=stream_id,
        headers=[
            (b":method", b"GET"),
            (b":scheme", b"http"),
            (b":authority", b"127.0.0.1"),
            (b":path", (f"/{path}").encode()),
            (b"user-agent", b"aioquic-loadtest"),
        ],
        end_stream=True,
    )
    protocol.transmit()
    
    await asyncio.wait_for(protocol.done_events[stream_id].wait(), timeout=15.0)
    return bytes(protocol.responses[stream_id])

async def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <port> <path1> <path2> ...")
        return

    port = int(sys.argv[1])
    paths = sys.argv[2:]

    config = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
    config.verify_mode = 0
    
    try:
        async with async_connect(
            "127.0.0.1",
            port,
            configuration=config,
            create_protocol=H3ClientProtocol,
            wait_connected=True,
        ) as protocol:
            tasks = [fetch_file(protocol, p) for p in paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for path, res in zip(paths, results):
                if isinstance(res, Exception):
                    print(f"FILE:{path}:ERROR:{res}")
                else:
                    md5 = hashlib.md5(res).hexdigest()
                    print(f"FILE:{path}:OK:{len(res)}:{md5}")
                    with open(f"tmp_h3_{path}", "wb") as f:
                        f.write(res)
                    print(f"DEBUG_DATA:{res[:100].hex()}")
    except Exception as e:
        print(f"AIOQUIC_ERROR: {e}")

if __name__ == "__main__":
    asyncio.run(main())
