# This script is called by fulltest_quic.py to perform aioquic-based client tests.

import asyncio
import sys
from aioquic.asyncio import connect as async_connect
from aioquic.quic.configuration import QuicConfiguration

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
            wait_connected=True,
        ) as protocol:
            reader, writer = await protocol.create_stream()
            writer.write(b"a" * 150)
            await writer.drain()
            # The server (now in H3 mode) should close the connection due to garbage
            await asyncio.sleep(2)
            writer.close()
            await writer.wait_closed()
    except Exception as e:
        # We expect a QuicConnectionError with H3_FRAME_ERROR (0x104) or similar
        print(f"CLIENT_EXPECTED_ERROR: {e}")

if __name__ == "__main__":
    asyncio.run(main())
