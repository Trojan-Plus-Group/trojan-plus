import asyncio
import sys
import os
import hashlib
import logging
import argparse
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

async def fetch_file(protocol, path, semaphore=None):
    if semaphore:
        async with semaphore:
            return await _fetch_file_impl(protocol, path)
    else:
        return await _fetch_file_impl(protocol, path)

async def _fetch_file_impl(protocol, path):
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
    
    await asyncio.wait_for(protocol.done_events[stream_id].wait(), timeout=30.0)
    return bytes(protocol.responses[stream_id])

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--file-list", type=str, help="Path to file containing list of files to download")
    parser.add_argument("--concurrency", type=int, default=0, help="Max parallel downloads (0 for unlimited)")
    parser.add_argument("paths", nargs="*", help="Files to download (if --file-list is not used)")
    args = parser.parse_args()

    paths = args.paths
    if args.file_list:
        if os.path.exists(args.file_list):
            with open(args.file_list, "r") as f:
                paths = [line.strip() for line in f if line.strip()]
        else:
            print(f"AIOQUIC_ERROR: file list {args.file_list} not found")
            return

    if not paths:
        print("AIOQUIC_ERROR: no files to download")
        return

    config = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
    config.verify_mode = 0
    
    semaphore = asyncio.Semaphore(args.concurrency) if args.concurrency > 0 else None

    try:
        async with async_connect(
            "127.0.0.1",
            args.port,
            configuration=config,
            create_protocol=H3ClientProtocol,
            wait_connected=True,
        ) as protocol:
            tasks = [fetch_file(protocol, p, semaphore) for p in paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for path, res in zip(paths, results):
                if isinstance(res, Exception):
                    print(f"FILE:{path}:ERROR:{res}")
                else:
                    md5 = hashlib.md5(res).hexdigest()
                    print(f"FILE:{path}:OK:{len(res)}:{md5}")
                    # Only write first few to avoid disk bloat in load test
                    if paths.index(path) < 5:
                        with open(f"tmp_h3_{hashlib.md5(path.encode()).hexdigest()[:8]}", "wb") as f:
                            f.write(res)
    except Exception as e:
        print(f"AIOQUIC_ERROR: {e}")

if __name__ == "__main__":
    asyncio.run(main())

