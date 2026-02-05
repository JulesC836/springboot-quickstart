#!/usr/bin/env bash

docker build -t springboot-quick-starter/auth ./auth-service
docker build -t springboot-quick-starter/discovry ./discovery
docker build -t springboot-quick-starter/gateway ./gateway


