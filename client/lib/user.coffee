{ convert: { bytesToBase64 } } = require 'bitcoinjs-lib'

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
  id = bytesToBase64 id if Array.isArray id
  xhr = $.get "/u/#{encodeURIComponent id}", {}, 'json'
  xhr.done (res) -> cb null, res
  xhr.fail (res) ->
    # 404s aren't considered an error, just send null as the result
    if res?.status is 404 then cb null, null
    else cb res


module.exports = { signup, load_user }
