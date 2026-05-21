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
        self.recv_size = 0

    def quic_event_received(self, event):
        for h3_event in self.h3.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                print(f"H3_EVENT: HeadersReceived stream={h3_event.stream_id}")
            if isinstance(h3_event, DataReceived):
                size = len(h3_event.data)
                self.recv_size += size  
                print(f"H3_EVENT: DataReceived stream={h3_event.stream_id} len={size} recv_size={self.recv_size}")
                self.responses[h3_event.stream_id] += h3_event.data
            if getattr(h3_event, 'stream_ended', False):
                print(f"H3_EVENT: StreamEnded stream={h3_event.stream_id}")
                if h3_event.stream_id in self.done_events:
                    self.done_events[h3_event.stream_id].set()

async def fetch_file(protocol, path, semaphore=None):
    if semaphore:
        async with semaphore:
            res = await _fetch_file_impl(protocol, path)
            return path, res
    else:
        res = await _fetch_file_impl(protocol, path)
    return path, res

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
    
    try:
        await asyncio.wait_for(protocol.done_events[stream_id].wait(), timeout=5.0)
    except TimeoutError:
        print(f"DEBUG_TIMEOUT: stream_id={stream_id} path={path} recv_len={len(protocol.responses[stream_id])}")
        debug_fname = f"debug_recv_{path}.bin"
        with open(debug_fname, "wb") as f:
            f.write(protocol.responses[stream_id])
        print(f"DEBUG_TIMEOUT: saved to {debug_fname}")
        raise
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

    print(f"AIOQUIC_STARTING: connecting to 127.0.0.1:{args.port}...")
    try:
        async with async_connect(
            "127.0.0.1",
            args.port,
            configuration=config,
            create_protocol=H3ClientProtocol,
            wait_connected=True,
        ) as protocol:
            print("AIOQUIC_CONNECTED")
            tasks = [fetch_file(protocol, p, semaphore) for p in paths]
            
            done_count = 0
            for fut in asyncio.as_completed(tasks):
                try:
                    path, res = await fut
                    done_count += 1
                    md5 = hashlib.md5(res).hexdigest()
                    print(f"FILE:{path}:OK:{len(res)}:{md5}")
                    if done_count % 1 == 0 or done_count == len(paths):
                        print(f"H3_PROGRESS: {done_count}/{len(paths)}")
                except Exception as e:
                    print(f"H3_FILE_ERROR: {e}")
                    done_count += 1
    except Exception as e:
        print(f"AIOQUIC_ERROR: {e}")

if __name__ == "__main__":
    asyncio.run(main())

