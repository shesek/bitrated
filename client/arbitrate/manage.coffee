{ render, iferr, error_displayer, parse_query, format_url } = require '../lib/util.coffee'
{ parse_key_bytes, get_address, ADDR_PRIV } = require '../../lib/bitcoin/index.coffee'
{ load_user } = require '../lib/user.coffee'
{ Crypto: { util: { randomBytes } } } = require 'bitcoinjs-lib'
view = require './views/manage.jade'
headsup_view = require './views/dialogs/heads-up.jade'

display_error = error_displayer $ '.content'

try
  { key, _is_new } = parse_query()
  { pub, priv } = parse_key_bytes key

  # When loaded for the first time, display the headsup message
  # and remove the _is_new flag from the URL
  if _is_new then do ->
    document.location.hash = format_url null, { _: (randomBytes 160), key }

    dialog = $ headsup_view {
      url: location.href
      has_priv: priv?
    }
    dialog.on 'hidden', -> dialog.remove()
    dialog.modal()


  load_user pub, iferr display_error, (user) ->
    render $ view {
      user
      priv: (priv? and get_address priv, ADDR_PRIV)
      current_url: document.location.href
    }

catch e then display_error e
