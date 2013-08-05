qs = require 'querystring'
{ Bitcoin, Crypto } = require '../lib/bitcoinjs-lib.js'
{ bytesToBase64, base64ToBytes } = Crypto.util
# { PRIVKEY_LEN } = require './bitcoin.coffee' # circular
PRIVKEY_LEN = 32
{ iferr, extend } = require '../util.coffee'

DEBUG = /(^|&)DEBUG(&|$)/.test location.hash.substr(1)

lpad = (bytes, len) -> bytes.unshift 0x00 while bytes.length<len; bytes

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

# Parse base64-encoded query string
parse_query = (str=document.location.hash.substr(1)) ->
  query = qs.parse str
  # Firefox decodes the hash, making the qs.parse() call decode it twice,
  # making "%2B" render as a space. Replacing this back to a plus sign
  # makes it work on Firefox.
  query[k] = base64ToBytes v.replace(/( )/g, '+') for k, v of query when v.length
  query

# Create query string for the given data, with base64 encoding
format_url = (data) ->
  is_sensitive = (data.bob?.length is PRIVKEY_LEN) or (data.key?.length is PRIVKEY_LEN)
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
  lpad, extend
  iferr, error_displayer
  parse_query, format_url, success, render
}
