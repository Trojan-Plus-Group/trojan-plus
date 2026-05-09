#!/bin/bash
# Start trojan client with client.json
cd "$(dirname "$0")"
../build/trojan -c client.json
