#!/bin/bash
# Package bitcoinjs-lib as a nodejs module

TARGET=lib/bitcoinjs-lib.js

# Wrap all of bitcoinjs-lib and its dependencies in an IIFE
# and export the Bitcoin, Crypto and BigInteger objects.
# (module is removed because bitcoinjs-lib partially
# attempts to identify and use it, which results in
# broken code)
echo 'module.exports = (function(module){' > $TARGET
( cd node_modules/bitcoinjs-lib/src/ && \
  for file in jsbn/{jsbn,jsbn2,prng4,rng,ec,sec}.js \
              crypto-js/{crypto,sha256,ripemd160}.js \
              events/eventemitter.js \
              {bitcoin,util,base58,address,ecdsa,eckey,opcode,script,transaction,message}.js \
  ; do
    cat $file
    echo ';'
  done \
) | uglifyjs -m >> $TARGET
echo 'BigInteger.sec={getSECCurveByName: getSECCurveByName};' >> $TARGET
echo 'return { Bitcoin: Bitcoin, Crypto: Crypto, BigInteger: BigInteger } ; })()' >> $TARGET

