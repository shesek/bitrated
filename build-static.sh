#!/bin/bash

rm -r build
mkdir build

cp -r public/{lib,img} build

browserify -e client/tx/index.coffee -t coffeeify -t jadeify2 -o build/tx.js
browserify -e client/arbitrate.coffee -t coffeeify -t jadeify2 -o build/arbitrate.js

stylus stylus -o build

jade views/*.jade -o build

