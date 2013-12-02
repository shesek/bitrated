{ Script, Address, Message, BigInteger, Opcode, Util, Crypto, convert, base58, ecdsa } = require 'bitcoinjs-lib'
getSECCurveByName = require 'bitcoinjs-lib/src/jsbn/sec'
{ sha256ripe160, numToBytes } = Util
{ charenc: { UTF8 }, util: { randomBytes } } = Crypto
{ bytesToHex, hexToBytes } = convert
{ OP_HASH160, OP_EQUAL } = Opcode.map

TESTNET = if window? then !!$('meta[name=testnet]').attr('content') else !!process.env.TESTNET

ADDR_PUB  = if TESTNET then 0x6f else 0x00
ADDR_P2SH = if TESTNET then 0xc4 else 0x05
ADDR_PRIV = if TESTNET then 0xef else 0x80
PRIVKEY_LEN = 32
PUBKEY_LEN = 65
ADDR_LEN = 20
PUBKEY_C_LEN = 33
PRIVKEY_C_LEN = 33
PRIVKEY_C_BYTE = 0x01

# Same as Crypto's SHA256, but for byte arrays by default
sha256 = (bytes) -> Crypto.SHA256 bytes, asBytes: true

# Triple SHA256
triple_sha256 = (bytes) -> sha256 sha256 sha256 bytes

# Turn a byte array to a bitcoin address
#
# If version is omitted, treats the first byte as the version
get_address = (bytes, version) ->
  unless version?
    version = bytes[0]
    bytes = bytes[1..]
  bytes = sha256ripe160 bytes if version in [ ADDR_PUB, ADDR_P2SH ] and bytes.length isnt ADDR_LEN
  Address::toString.call { version, hash: bytes }

# Parse and validate base58 Bitcoin addresses
#
# Validates and strips the checksum, and optionally the expected version byte
parse_address = (address, version) ->
  bytes = base58.decode address
  checksum = sha256 sha256 bytes[0...-4]
  throw new Error 'Invalid address checksum' for i in [0..3] when bytes[bytes.length-4+i] isnt checksum[i]
  if version?
    throw new Error 'Invalid address version' unless version is bytes[0]
    switch version
      when ADDR_PUB, ADDR_P2SH
        throw new Error 'Invalid address length' unless bytes.length-5 is ADDR_LEN
      when ADDR_PRIV
        throw new Error 'Invalid private key format' unless (bytes.length-5 is PRIVKEY_LEN) or \
                                                            (bytes.length-5 is PRIVKEY_C_LEN and bytes[33] is PRIVKEY_C_BYTE)
    bytes[1...-4]
  else bytes[0...-4]

# Get the public key of a private key
#
# priv can be an BigInteger or an byte array (optionally with the compressed
# flag)
get_pub = (priv, compressed) ->
  unless priv instanceof BigInteger
    if priv.length is PRIVKEY_LEN
      secexp = BigInteger.fromByteArrayUnsigned priv
    else if (priv.length is PRIVKEY_C_LEN) and (priv[priv.length-1] is PRIVKEY_C_BYTE)
      compressed ?= true
      secexp = BigInteger.fromByteArrayUnsigned priv[...-1]
    else
      throw new Error 'Invalid private key'
  else secexp = priv

  (getSECCurveByName 'secp256k1')
    .getG().multiply(secexp)
    .getEncoded(compressed)

# Creates an 2-of-3 multisig
create_multisig = (pubkeys) ->
  # order pubkeys to ensure the same multisig address
  # regardless of the original order
  pubkeys = pubkeys.map(bytesToHex).sort().map(hexToBytes)
  script = Script.createMultiSigOutputScript 2, pubkeys
  address = get_address script.buffer, ADDR_P2SH
  { pubkeys, script, address }

# Create an output script for the given pubkey/script address
create_out_script = (address) ->
  address = parse_address address unless Array.isArray address

  [ version, hash... ] = address
  switch version
    when ADDR_PUB then Script.createOutputScript hash
    when ADDR_P2SH
      script = new Script
      script.writeOp OP_HASH160
      script.writeBytes hash
      script.writeOp OP_EQUAL
      script
    else throw new Error 'Invalid address version'

# Get the textual address of an output script
#
# Supports p2sh and regular pay-to-pubkey scripts
get_script_address = do(
  is_p2sh = ({ chunks }) -> chunks.length is 3 and chunks[0] is OP_HASH160 and chunks[2] is OP_EQUAL
) -> (script) ->
  if is_p2sh script
    get_address script.chunks[1], ADDR_P2SH
  else get_address script.toScriptHash(), ADDR_PUB

module.exports = {
  TESTNET
  ADDR_P2SH, ADDR_PUB, ADDR_PRIV, PRIVKEY_LEN, PUBKEY_LEN, ADDR_LEN
  PUBKEY_C_LEN, PRIVKEY_C_LEN, PRIVKEY_C_BYTE
  get_address, get_pub, parse_address, get_script_address
  create_multisig, create_out_script, sha256, triple_sha256
}
