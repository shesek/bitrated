qs = require 'querystring'
{ Bitcoin, Crypto } = require '../lib/bitcoinjs-lib.js'
{ SHA256, util: { bytesToBase64  } } = Crypto
# { PRIVKEY_LEN } = require './bitcoin.coffee' # circular
PRIVKEY_LEN = 32
{ iferr, extend } = require '../util.coffee'

DEBUG = /(^|&)DEBUG(&|$)/.test location.hash.substr(1)

lpad = (bytes, len) -> bytes.unshift 0x00 while bytes.length<len; bytes
sha256b = (bytes) -> SHA256 bytes, asBytes: true

# given a container element, returns a function that displays an error in it
error_displayer = (container) -> (e) ->
  unless (el = container.find '.error').length
    el = $(document.createElement 'div')
      .addClass('error alert alert-error')
      .append('<button type="button" class="close" data-dismiss="alert">&times;</button>')
      .append('<p></p>')
      .prependTo(container)
  el.find('p').text(e.message ? e).end().show()
  throw e if DEBUG


# Create query string for the given data, with base64 encoding
format_url = (data) ->
  is_sensitive = data.bob?.length is PRIVKEY_LEN
  query = {}
  for name, val of data when val?
    query[name] = if Array.isArray val then bytesToBase64 val \
                  else val
  (if is_sensitive then 'DO-NOT-SHARE&' else '') + \
  #(if TESTNET      then 'TESTNET&'      else '') + \
  qs.stringify query

# returns a function that dispalys the given success message
success = do (view = require './views/dialog-success.jade') -> (message) -> ->
  dialog = $ view { message }
  dialog.on 'hidden', -> do dialog.remove
  dialog.modal()

# Render an element as the primary content
render = do ($root = $ '.content') -> (el) ->
  $root.empty().append(el)
  el.find('[data-toggle=tooltip]').tooltip()
  el.find('[data-toggle=popover]').popover()

module.exports = {
  lpad, sha256b, extend
  iferr, error_displayer
  format_url, success, render
}
