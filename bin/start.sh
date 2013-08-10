#!/bin/bash
[ -f .env ]  && source .env

./node_modules/.bin/coffee ./server/app.coffee "$@"

