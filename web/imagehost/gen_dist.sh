#!/bin/sh
rm dist/imagehost.zip
zip -r dist/imagehost.zip src/
mkdir -p tmp/src
cp dist.Dockerfile tmp/src/Dockerfile
cd tmp
zip ../dist/imagehost.zip src/Dockerfile
cd ..
rm -rf tmp