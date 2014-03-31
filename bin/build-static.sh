#!/bin/bash
[ -f .env ]  && source .env
[ ! -z "$1" ] && TARGET="$1"
[ -z "$TARGET" ] && echo "Usage: TARGET=build_target npm run build-static, or set TARGET in .env" && exit 1

echo "Preparing target..."
rm -r $TARGET
mkdir $TARGET
mkdir $TARGET/{tx,arbitrate,help}

echo "Copying static files..."
cp -r public/{lib,img,lato} $TARGET

echo "Browserifying..."
for file in tx/new tx/join tx/multisig arbitrate/new arbitrate/manage; do
  echo "  - $file"
  browserify -e client/$file.coffee -t coffeeify -t jadeify2 | uglifyjs -m -c > $TARGET/$file.js
done

echo "Compiling stylus..."
stylus --compress public/*.styl -o $TARGET

echo "Compiling jade..."
read -d '' LOCALS <<JSON
  {
    "url": "${URL}",
    "testnet": "${TESTNET}",
    "testnet_api": "${TESTNET_API}",
    "ver": "${VER}"
  }
JSON
jade pages/*.jade -o $TARGET --obj "$LOCALS"
jade pages/help/*.jade -o $TARGET/help --obj "$LOCALS"

