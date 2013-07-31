{ Bitcoin, Crypto, BigInteger } = require '../lib/bitcoinjs-lib.js'
{ sha256b } = require './util.coffee'
{ ECDSA, ECKey, Script, Address, Base58, Message } = Bitcoin
{ sha256ripe160 } = Bitcoin.Util
{ randomBytes, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes } = Crypto.util
{ UTF8 } = Crypto.charenc
{ getSECCurveByName } = BigInteger.sec
{ OP_HASH160, OP_EQUAL } = Bitcoin.Opcode.map

TESTNET = !!~document.location.hash.indexOf('TESTNET')

ADDR_PUB  = if TESTNET then 0x6f else 0x00
ADDR_P2SH = if TESTNET then 0xc4 else 0x05
ADDR_PRIV = if TESTNET then 0xef else 0x80
PRIVKEY_LEN = 32
PUBKEY_LEN = 65
ADDR_LEN = 20
#PUBKEY_COMPRESS_LEN = 33 # not supported yet

# Turn a byte array to a bitcoin address
get_address = (hash, version) ->
  [ version, hash... ] = hash unless version?
  hash = sha256ripe160 hash if version in [ ADDR_PUB, ADDR_P2SH ] and hash.length isnt ADDR_LEN
  Address::toString.call { version, hash }

# Get the public key of a private key
get_pub = (secexp, compressed=false) ->
  secexp = BigInteger.fromByteArrayUnsigned secexp unless secexp instanceof BigInteger
  (getSECCurveByName 'secp256k1')
    .getG().multiply(secexp)
    .getEncoded(compressed)

# Creates an 2-of-3 multisig
create_multisig = (pubkeys) ->
  # order pubkeys to ensure the same multisig address
  # regardless of the order
  pubkeys = pubkeys.map(bytesToHex).sort().map(hexToBytes)
  script = Script.createMultiSigOutputScript 2, pubkeys
  address = get_address script.buffer, ADDR_P2SH
  { pubkeys, script, address }

# Create an output script for the given pubkey/script address
create_out_script = (address) ->
  address = parse_address address unless Array.isArray address
  [ version, hash... ] = address
  switch version
    when ADDR_PUB then Script.createOutputScript { hash }
    when ADDR_P2SH
      script = new Script
      script.writeOp OP_HASH160
      script.writeBytes hash
      script.writeOp OP_EQUAL
      script
    else throw new Error 'Invalid payment address version'

get_script_address = do(
  is_p2sh = ({ chunks }) -> chunks.length is 3 and chunks[0] is OP_HASH160 and chunks[2] is OP_EQUAL
) -> (script) ->
  if is_p2sh script
    get_address script.chunks[1], ADDR_P2SH
  else get_address script.simpleOutHash(), ADDR_PUB

# Parse and validate base58 Bitcoin addresses
# Validates and strips the checksum, and optionally the expected version byte
parse_address = (address, version) ->
  bytes = Base58.decode address
  checksum = sha256b sha256b bytes[0...-4]
  throw new Error 'Invalid address checksum' for i in [0..3] when bytes[bytes.length-4+i] isnt checksum[i]
  if version?
    throw new Error 'Invalid address version' unless version is bytes[0]
    switch version
      when ADDR_PUB, ADDR_P2SH
        throw new Error 'Invalid address length' unless bytes.length-5 is ADDR_LEN
      when ADDR_PRIV
        throw new Error 'Invalid private key length' unless bytes.length-5 is PRIVKEY_LEN
    bytes[1...-4]
  else bytes[0...-4]


# Parse and validate public key bytes or hex string
parse_pubkey = (bytes) ->
  bytes = hexToBytes bytes unless Array.isArray bytes
  throw new Error 'Invalid public key length' unless bytes.length is PUBKEY_LEN
  bytes

# Generate random private key
random_privkey = ->
  # Use crypto.getRandomValues() if available
  if window.crypto?.getRandomValues?
    random = new Uint8Array 32
    crypto.getRandomValues random
    Array.apply [], random
  # And fallback to Math.random()-based randomBytes
  else randomBytes 32

# Verify the signature matches the public key
verify_sig = (expected_pub, message, sig) ->
  sig = ECDSA.parseSigCompact sig
  hash = Message.getHash UTF8.bytesToString message
  compressed = !!(sig.i & 4)
  actual_pub = ECDSA.recoverPubKey(sig.r, sig.s, hash, sig.i).getPubPoint().getEncoded(compressed)
  (bytesToHex actual_pub) is (bytesToHex expected_pub)

sign_message = (priv, message) ->
  base64ToBytes Message.signMessage (new ECKey priv), UTF8.bytesToString message

# Parse an hex-encoded public key or base58check-encoded private key
parse_key_string = do(
  PUBKEY  = /^[a-f0-9]{130}$/
  PRIVKEY = ///^#{if TESTNET then '9' else '5'}[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50}$///
) -> (key) ->
  if PUBKEY.test key
    { pub: parse_pubkey key }
  else if (PRIVKEY.test key) and (priv = try parse_address key, ADDR_PRIV)?
    { priv, pub: get_pub priv }
  else
    throw new Error 'Invalid public/private key'

# Parse public/private key from bytes
parse_key_bytes = (bytes) -> switch bytes.length
  when PUBKEY_LEN  then pub: bytes
  when PRIVKEY_LEN then pub: (get_pub bytes), priv: bytes
  else throw new Error 'Invalid public/private key'

module.exports = {
  ADDR_P2SH, ADDR_PUB, ADDR_PRIV, PRIVKEY_LEN, PUBKEY_LEN, ADDR_LEN
  get_address, get_pub, parse_address, parse_pubkey, get_script_address
  create_multisig, create_out_script, random_privkey
  sign_message, verify_sig
  parse_key_string, parse_key_bytes
}
