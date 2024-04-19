#!/bin/bash
cd ./deploy
sudo docker buildx build --platform linux/amd64 -t burgercoin .

IMAGE="burgercoin"
PORT="31337"
HTTP_PORT="8545"
ETH_RPC_URL="https://sepolia.infura.io/v3/904164941ac34c29a874d9371ffa42d6"
FLAG="bctf{you_made_b01lerburgers_go_bankrupt_rip}"
PUBLIC_IP="ctf.b01lers.com" #change this
SHARED_SECRET="$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM"
# sh run.sh burgercoin 31337 8545 
# https://eth-sepolia.g.alchemy.com/v2/Nd6p2drzfAma1nLNQi-HtZhWsWOHqrVj

echo "[+] running challenge"
exec docker run -d \
    -e "PORT=$PORT" \
    -e "HTTP_PORT=$HTTP_PORT" \
    -e "ETH_RPC_URL=$ETH_RPC_URL" \
    -e "FLAG=$FLAG" \
    -e "PUBLIC_IP=$PUBLIC_IP" \
    -e "SHARED_SECRET=$SHARED_SECRET" \
    -p "$PORT:$PORT" \
    -p "$HTTP_PORT:$HTTP_PORT" \
    "$IMAGE"
