#!/bin/bash
CDIR="$(cd "$(dirname "$0")" && pwd)"
python3 "$CDIR/http1_server.py"
