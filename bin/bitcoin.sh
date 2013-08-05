#!/bin/bash
# Package bitcoinjs-lib as a nodejs module

[[ $TARGET ]] || TARGET=lib/bitcoinjs-lib.js
[[ $MINIFY ]] && minify_cmd='uglifyjs -m' || minify_cmd='cat'

# Wrap all of bitcoinjs-lib and its dependencies in an IIFE
# and export the Bitcoin, Crypto and BigInteger objects.
# (module is removed because bitcoinjs-lib partially
# attempts to identify and use it, which results in
# broken code)
echo 'module.exports = (function(module){' > $TARGET
echo 'var navigator={}, window=global;' >> $TARGET
( cd node_modules/bitcoinjs-lib/src/ && \
  for file in jsbn/{jsbn,jsbn2,prng4,rng,ec,sec}.js \
              crypto-js/{crypto,sha256,ripemd160}.js \
              events/eventemitter.js \
              {bitcoin,util,base58,address,ecdsa,eckey,opcode,script,transaction,message}.js \
  ; do
    cat $file
    echo ';'
  done \
) | $minify_cmd >> $TARGET
echo 'BigInteger.sec={getSECCurveByName: getSECCurveByName};' >> $TARGET
echo 'return { Bitcoin: Bitcoin, Crypto: Crypto, BigInteger: BigInteger } ; })()' >> $TARGET

