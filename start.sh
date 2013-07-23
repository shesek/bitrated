#!/bin/bash
[ -f .env ]  && source .env

./node_modules/.bin/coffee app.coffee "$@"

