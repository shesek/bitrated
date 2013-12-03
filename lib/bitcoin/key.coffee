{ Message, Key: ECKey, Crypto, Util, convert, ecdsa } = require 'bitcoinjs-lib'
{ charenc: { UTF8 } } = Crypto
{ numToBytes } = Util
{ bytesToHex, hexToBytes } = convert
{ get_pub, sha256, parse_address, parse_pubkey
  TESTNET, ADDR_PRIV
  PUBKEY_LEN, PRIVKEY_LEN, PUBKEY_C_LEN, PRIVKEY_C_LEN, PRIVKEY_C_BYTE
} = require './index.coffee'
lazy = require 'lazy-prop'

module.exports = class Key
  constructor: (type, bytes) ->
    @[type] = bytes
    if type is 'priv'
      lazy this, pub: -> get_pub bytes

  lazy @::,
    # Get an ECKey instance of this key
    eckey: ->
      if @priv then new ECKey @priv
      else throw new Error 'Cannot make ECKey of unknown private key'

    # Check if its compressed key
    is_compressed: -> @pub.length is PUBKEY_C_LEN

  # Sign message
  # todo replace sign_message, verify_sig
  sign_message: (message) ->
    hexToBytes Message.signMessage @eckey, (UTF8.bytesToString message), @is_compressed

  # Verify the message signature matches the public key
  verify_sig: (message, sig) ->
    sig = ecdsa.parseSigCompact sig
    hash = Message.getHash if Array.isArray message then UTF8.bytesToString message else message
    compressed = !!(sig.i & 4)
    actual_pub = ecdsa.recoverPubKey(sig.r, sig.s, hash, sig.i).getPubPoint().getEncoded(compressed)
    (bytesToHex actual_pub) is (bytesToHex @pub)

# Generate random key pair
#
# Based on crypto.getRandomValues, Math.random and the current time
Key.random = (compressed=true) ->
  throw new Error 'crypto.getRandomValues() is required' unless window.crypto?.getRandomValues?

  window.crypto.getRandomValues crypto_random = new Uint8Array 32
  crypto_random = Array.apply [], crypto_random

  math_random = numToBytes Math.random()*Math.pow(2,53)

  time = numToBytes Date.now()

  priv = sha256 [ crypto_random..., math_random..., time... ]
  priv.push PRIVKEY_C_BYTE if compressed

  new Key 'priv', priv

# Returns a new Key instance from public key hex string or byte array
Key.from_pubkey = (pub) ->
  throw new Error 'Empty public key' unless pub?.length
  pub = hexToBytes pub if typeof pub is 'string'
  throw new Error 'Invalid public key length' unless pub.length in [ PUBKEY_LEN, PUBKEY_C_LEN ]
  new Key 'pub', pub

# Returns a new Key instance from private key in base58 encoding or byte array
Key.from_privkey = (priv) ->
  priv = parse_address priv, ADDR_PRIV if typeof priv is 'string'
  throw new Error 'Invalid private key length' unless priv.length in [ PRIVKEY_LEN, PRIVKEY_C_LEN ]
  new Key 'priv', priv

# Returns a new Key instance from an hex-encoded public key or base58check-encoded private key
Key.from_string = do(
  PUBKEY  = /^([a-f0-9]{130}|[a-f0-9]{66})$/
  PRIVKEY = ///^(
    #{if TESTNET then '9' else '5'}[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50}
   |[#{if TESTNET then 'c' else 'KL'}][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{51}
  )$///
) -> (key) -> switch
  when PUBKEY.test key  then Key.from_pubkey key
  when PRIVKEY.test key then Key.from_privkey key
  else throw new Error 'Invalid public/private key'
