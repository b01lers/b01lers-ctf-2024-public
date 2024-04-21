#!/bin/bash

docker build . -f ./deploy/Dockerfile -tlocalhost:5000/libraryofphp:latest
docker push localhost:5000/libraryofphp:latest
kubectl create -f ./deploy/workloads.yaml

