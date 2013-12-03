#!/bin/bash
[ -f .env ]  && source .env

# Kill child process on exit
trap 'kill $(jobs -p)' EXIT

# Re-run server on crashes
while :
do
  ./node_modules/.bin/coffee ./server/app.coffee "$@"
  echo "Server crashed with status $?"
  sleep 1
done

