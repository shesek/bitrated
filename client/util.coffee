{ SHA256 } = Crypto

DEBUG = /(^|&)DEBUG(&|$)/.test location.hash.substr(1)

noop = ->
lpad = (bytes, len) -> bytes.unshift 0x00 while bytes.length<len; bytes
sha256b = (bytes) -> SHA256 bytes, asBytes: true
extend = (dest, source) -> dest[k]=v for own k, v of source when source[k]?; dest

iferr = (errfn=noop, succfn=noop) -> (err, a...) -> if err? then errfn err else succfn a...

# given a container element, returns a function that displays an error
error_displayer = (container) -> (e) ->
  unless (el = container.find '.error').length
    el = $(document.createElement 'div')
      .addClass('error alert alert-error')
      .append('<button type="button" class="close" data-dismiss="alert">&times;</button>')
      .append('<p></p>')
      .prependTo(container)
  el.find('p').text(e.message ? e).end().show()
  throw e if DEBUG

module.exports = {
  lpad, sha256b, extend
  iferr, error_displayer
}
