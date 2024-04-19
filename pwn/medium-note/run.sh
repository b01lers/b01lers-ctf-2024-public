#!/bin/bash
cd ./deploy
sudo docker-compose up --build --remove-orphans  -d
