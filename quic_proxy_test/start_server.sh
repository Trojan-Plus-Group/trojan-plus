#!/bin/bash
# Start trojan server with server.json
cd "$(dirname "$0")"
../build/trojan -c server.json
