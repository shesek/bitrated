{ render, iferr, error_displayer, parse_query, format_url } = require '../lib/util.coffee'
{ parse_key_bytes, get_address, ADDR_PRIV } = require '../../lib/bitcoin/index.coffee'
Key = require '../../lib/bitcoin/key.coffee'
{ load_user } = require '../lib/user.coffee'
{ Crypto: { util: { randomBytes } } } = require 'bitcoinjs-lib'
view = require './views/manage.jade'
headsup_view = require './views/dialogs/heads-up.jade'

display_error = error_displayer $ '.content'

try
  { key, key_priv,_is_new } = parse_query()
  if key_priv? then key = Key.from_privkey key_priv
  else if key? key = Key.from_pubkey key
  else throw new Error 'Missing key argument'
catch e then display_error e

# When loaded for the first time, display the headsup message
# and remove the _is_new flag from the URL
if _is_new then do ->
  document.location.hash = format_url null, { _: (randomBytes 160), key }

  dialog = $ headsup_view {
    url: location.href
    has_priv: key.priv?
  }
  dialog.on 'hidden', -> dialog.remove()
  dialog.modal()


load_user key.pub, iferr display_error, (user) ->
  return display_error 'User cannot be found' unless user?
  render $ view {
    user
    priv: (key.priv? and get_address key.priv, ADDR_PRIV)
  }

