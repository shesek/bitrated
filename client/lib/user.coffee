{ Crypto } = require '../../lib/bitcoinjs-lib.js'
{ bytesToBase64 } = Crypto.util

# Create new user
signup = (user, cb) ->
  data = Object.create user
  data.pubkey = bytesToBase64 user.pubkey
  data.sig = bytesToBase64 user.sig
  $.post('/u', data, 'json')
    .done((res) -> cb null, res)
    .fail((res) -> cb (try JSON.parse res.responseText) or res)

# Load user
# id can be either username, pubkey byte array or pubkey hash byte array
load_user = (id, cb) ->
  if Array.isArray id
    id = bytesToBase64 id
  $.get("/u/#{encodeURIComponent id}", {}, 'json')
    .done((res) -> cb null, res)
    .fail(cb)

module.exports = { signup, load_user }
