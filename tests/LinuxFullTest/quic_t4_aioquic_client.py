# This script is called by fulltest_quic.py to perform aioquic-based client tests.

import asyncio
import sys
from aioquic.asyncio import connect as async_connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.response_data = b""
        self.done = asyncio.Event()

    def quic_event_received(self, event):
        for h3_event in self.h3.handle_event(event):
            if isinstance(h3_event, DataReceived):
                self.response_data += h3_event.data
            if getattr(h3_event, 'stream_ended', False):
                self.done.set()

async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <port>")
        return

    port = int(sys.argv[1])
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
            stream_id = protocol._quic.get_next_available_stream_id()
            protocol.h3.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"127.0.0.1"),
                    (b":path", b"/"),
                    (b"user-agent", b"X" * 150),
                ],
                end_stream=True,
            )
            protocol.transmit()

            try:
                await asyncio.wait_for(protocol.done.wait(), timeout=5.0)
                print("RESPONSE:", protocol.response_data.decode('utf-8', errors='replace'))
            except asyncio.TimeoutError:
                print("RESPONSE_TIMEOUT")
    except Exception as e:
        print(f"AIOQUIC_ERROR: {e}")

if __name__ == "__main__":
    asyncio.run(main())
