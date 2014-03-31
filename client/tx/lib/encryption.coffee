triplesec = require 'triplesec'
{ convert: { bytesToBase64, base64ToBytes, hexToBytes } } = require 'bitcoinjs-lib'
{ iferr } = require '../../../lib/util.coffee'
{ Scrypt } = require 'triplesec/lib/scrypt'
{ prng, HMAC_SHA256 } = triplesec

TS_VER = 10

# Custom version to use a very minimal key strecthing work factor.
# The encryption key is randomly generated, no point in stretching it.
triplesec.V[TS_VER] =
  header           : [ 0x1c94d7de, TS_VER ] # The magic #, and also the version #
  salt_size        : 16                     # 16 bytes of salt for various uses
  xsalsa20_rev     : false                  # XSalsa20 Endian Reverse
  kdf              :                        # The key derivation...
    klass          : Scrypt                 #   algorithm klass
    opts           :                        #   ..and options
      c            : 1                      #   The number of iterations
      klass        : HMAC_SHA256            #   The HMAC to use as a subroutine
      N            : 2                      #   log_2 of the work factor
      r            : 8                      #   The memory use factor
      p            : 1                      #   the parallelization factor
  hmac_key_size    : 768/8                  # The size of the key to split over the two HMACs.

# Encrypt/decrypt
encrypt = (secret, pt, cb) ->
  triplesec.encrypt {
    data: new Buffer pt
    key: new Buffer secret
    version: TS_VER
  }, iferr cb, (buff) ->
    cb null, buff.toString 'base64'
decrypt = (secret, enc, cb) ->
  triplesec.decrypt {
    data: new Buffer enc, 'base64'
    key: new Buffer secret
    version: TS_VER
  }, iferr cb, (buff) ->
    cb null, buff.toString()


# Encrypt/decrypt byte array
encrypt_ba = (secret, ba, cb) ->
  encrypt secret, (bytesToBase64 ba), cb
decrypt_ba = (secret, enc, cb) ->
  decrypt secret, enc, iferr cb, (pt) ->
    cb null, base64ToBytes pt

# Encrypt/decrypt flat JSON objects of byte arrays
encrypt_jsonba = (secret, obj, cb) ->
  nobj = {}
  nobj[key] = bytesToBase64 val for key, val of obj
  encrypt secret, (JSON.stringify nobj), cb
decrypt_jsonba = (secret, enc, cb) ->
  decrypt secret, enc, iferr cb, (pt) ->
    try
      obj = JSON.parse pt
      nobj = {}
      nobj[key] = base64ToBytes val for key, val of obj
      cb null, nobj
    catch err then cb err

# Generate a 32-bytes random key
gen_key = (cb) ->
  prng.generate 32, (key) ->
    # Convert from WordArray to a regular byte array
    cb null, hexToBytes key.to_hex()

module.exports = {
  encrypt, decrypt
  encrypt_ba, decrypt_ba
  encrypt_jsonba, decrypt_jsonba
  gen_key
}
