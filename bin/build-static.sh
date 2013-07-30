#!/bin/bash
[ -f .env ]  && source .env
[ ! -z "$1" ] && BUILD="$1"
[ -z "$BUILD" ] && echo "Usage: BUILD=build_target npm run build-static, or set BUILD in .env" && exit 1

rm -r "$BUILD"
mkdir "$BUILD"

cp -r public/{lib,img} "$BUILD"

browserify -e client/tx/index.coffee -t coffeeify -t jadeify2 -o "$BUILD/tx.js"
browserify -e client/arbitrate.coffee -t coffeeify -t jadeify2 -o "$BUILD/arbitrate.js"

stylus stylus -o "$BUILD"

read -d '' LOCALS <<JSON
  {
    "pubkey_address": "${PUBKEY_ADDRESS}",
    "url": "${URL}",
    "api": "${API_URL}"
  }
JSON
jade views/*.jade -o "$BUILD" --obj "$LOCALS"

