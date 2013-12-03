{ render, iferr, error_displayer, parse_query, format_url } = require '../lib/util.coffee'
{ parse_key_bytes, get_address, ADDR_PRIV, ADDR_PUB } = require '../../lib/bitcoin/index.coffee'
Key = require '../../lib/bitcoin/key.coffee'
{ load_user, update_user } = require '../lib/user.coffee'
{ Crypto: { util: { randomBytes } }, convert: { bytesToBase64 } } = require 'bitcoinjs-lib'
sign_message = require '../sign-message.coffee'
view = require './views/manage.jade'
headsup_view = require './views/dialogs/heads-up.jade'

display_error = error_displayer $ '.content'

try
  { key, key_priv,_is_new } = query_args = parse_query()
  if key_priv? then key = Key.from_privkey key_priv
  else if key? then key = Key.from_pubkey key
  else throw new Error 'Missing key argument'
catch e then return display_error e

# When loaded for the first time, display the headsup message
# and remove the _is_new flag from the URL
if _is_new then do ->
  delete query_args._is_new
  document.location.hash = format_url null, query_args

  dialog = $ headsup_view {
    url: location.href
    has_priv: key.priv?
  }
  dialog.on 'hidden', -> dialog.remove()
  dialog.modal backdrop: 'static', keyboard: false

load_user key.pub, iferr display_error, (user) ->
  return display_error 'User cannot be found' unless user?
  render el = $ view {
    user
    address: get_address key.pub, ADDR_PUB
    priv: (key.priv? and get_address key.priv, ADDR_PRIV)
  }

  el.find('.update-terms').submit (e) ->
    e.preventDefault()
    $this = $ this

    terms = $this.find('textarea[name=terms]').val()
    saved_message = $this.find('.saved-success').hide()
    sign_message key, terms, iferr display_error, (sig) ->
      button = $this.find('button').addClass('active').attr('disabled', true)
      update_user user.username, terms, sig, (err) ->
        button.removeClass('active').attr('disabled', false)
        return display_error err if err?
        saved_message.show()
        el.find('.sig').text bytesToBase64 sig
