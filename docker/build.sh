#!/usr/bin/env bash
# Build the ClawP2P agent base image locally.
# No Docker Hub account required.
set -euo pipefail

IMAGE="clawp2p/agent-base:0.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building $IMAGE from $SCRIPT_DIR/Dockerfile ..."
docker build -t "$IMAGE" "$SCRIPT_DIR"

echo ""
echo "Verifying python3.11 inside image ..."
docker run --rm "$IMAGE" python3.11 --version

echo ""
echo "Done. Image ready: $IMAGE"
echo "To verify uid: docker run --rm $IMAGE id"
