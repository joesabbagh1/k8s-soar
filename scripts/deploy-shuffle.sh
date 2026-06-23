#!/usr/bin/env bash
set -euo pipefail

echo ">>> Adding Shuffle Helm repo"
helm repo add shuffle https://frikky.github.io/Shuffle
helm repo update

echo ">>> Installing Shuffle in shuffle namespace"
helm upgrade --install shuffle shuffle/shuffle \
  --namespace shuffle --create-namespace \
  --set opensearch.enabled=true \
  --set backend.image.tag=latest

echo ">>> Shuffle deployed. Please wait for pods to be ready."
echo ">>> After Shuffle is running, create a webhook in Shuffle and update values.yaml with the webhook URL."
