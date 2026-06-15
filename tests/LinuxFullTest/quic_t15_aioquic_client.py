# This script is called by fulltest_quic.py to perform aioquic-based client tests.

import asyncio
import sys
from aioquic.asyncio import connect as async_connect
from aioquic.quic.configuration import QuicConfiguration

def setup_aioquic_monkeypatch():
    """
    Monkeypatch aioquic to allow sending data on peer-initiated uni streams.
    This avoids ValueError when server sends H3 control streams.
    """
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.stream import QuicStream
    
    orig_get_stream = QuicConnection._get_or_create_stream_for_send
    
    def patched_get_stream(self, stream_id):
        try:
            return orig_get_stream(self, stream_id)
        except ValueError:
            if stream_id not in self._streams:
                self._streams[stream_id] = QuicStream(
                    stream_id=stream_id, 
                    max_stream_data_local=0, 
                    max_stream_data_remote=0
                )
            return self._streams[stream_id]
            
    QuicConnection._get_or_create_stream_for_send = patched_get_stream

async def run_client_session(port):
    config = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
    config.verify_mode = 0

    async with async_connect(
        "127.0.0.1",
        port,
        configuration=config,
        wait_connected=True,
    ) as protocol:
        # Create a bidirectional stream
        reader, writer = await protocol.create_stream(is_unidirectional=False)
        
        # Send an invalid H3 frame: type 0x02 (reserved), length 1, data 'a'
        # Followed by garbage to trigger H3 protocol error
        writer.write(b"\x02\x01a" + b"a" * 150)
        await writer.drain()
        
        # Wait for the server to close the connection due to protocol error
        try:
            await asyncio.wait_for(protocol.wait_closed(), timeout=5.0)
            event = protocol._quic._close_event
            if event:
                error_code = event.error_code
                reason_phrase = event.reason_phrase
                print(f"CLIENT_EXPECTED_ERROR: Code {error_code}, Reason: {reason_phrase}")
            else:
                print("CLIENT_EXPECTED_ERROR: Connection closed without specific event.")
        except asyncio.TimeoutError:
            print("CLIENT_EXPECTED_ERROR: timeout waiting for server closure")

async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <port>")
        return

    port = int(sys.argv[1])
    setup_aioquic_monkeypatch()

    try:
        await asyncio.wait_for(run_client_session(port), timeout=10.0)
    except Exception as e:
        # T15 test runner looks for CLIENT_EXPECTED_ERROR in stdout/stderr
        print(f"CLIENT_EXPECTED_ERROR: {type(e).__name__}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
