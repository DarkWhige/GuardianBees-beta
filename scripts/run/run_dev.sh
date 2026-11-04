#!/usr/bin/env bash

docker compose --env-file .env.backend down
docker compose --env-file .env.backend up --build