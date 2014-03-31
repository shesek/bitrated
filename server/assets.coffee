stylus = require 'stylus'
express = require 'express'
{ basename, join } = require 'path'
browserify = do (browserify = require 'browserify-middleware') ->
  (path) -> browserify path, transform: [ 'coffeeify', 'jadeify2' ]

pages_dir = join __dirname, '..', 'pages'
scripts = [ 'tx/new', 'tx/join', 'tx/multisig', 'arbitrate/new', 'arbitrate/manage' ]

module.exports = ->
  @set 'public', join __dirname, '..', 'public'

  @use stylus.middleware src: @settings.public
  @use express.static @settings.public, maxAge: 86400000 # one day

  for script in scripts
    @get "/#{script}.js", browserify "../client/#{script}.coffee"

  @get '/', (req, res) -> res.render join pages_dir, 'index'
  @get '/*.html', (req, res) -> res.render join pages_dir, req.url.replace /\.html$/, ''
