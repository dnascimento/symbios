#!/bin/bash

docker build -t symbios/base base
docker build -t symbios/ca ca
docker build -t symbios/container container