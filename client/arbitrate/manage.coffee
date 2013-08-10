{ render, iferr, error_displayer, parse_query } = require '../lib/util.coffee'
{ parse_key_bytes, get_address, ADDR_PRIV } = require '../../lib/bitcoin.coffee'
{ load_user } = require '../lib/user.coffee'
view = require './views/manage.jade'

display_error = error_displayer $ '.content'

try
  { key } = parse_query()
  { pub, priv } = parse_key_bytes key
  load_user pub, iferr display_error, (user) ->
    render $ view {
      user
      priv: (priv? and get_address priv, ADDR_PRIV)
      current_url: document.location.href
    }

catch e then display_error e
