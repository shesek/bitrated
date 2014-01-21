stylus = require 'stylus'
express = require 'express'
{ basename, join } = require 'path'
browserify = do (browserify = require 'browserify-middleware') ->
  (path) -> browserify path, transform: [ 'coffeeify', 'jadeify2' ]

pages_dir = join __dirname, '..', 'pages'

module.exports = ->
  @set 'public', join __dirname, '..', 'public'

  @use stylus.middleware src: @settings.public
  @use express.static @settings.public, maxAge: 86400000 # one day

  @get '/home.js', browserify '../client/home.coffee'

  @get '/tx/new.js', browserify '../client/tx/new.coffee'
  @get '/tx/join.js', browserify '../client/tx/join.coffee'
  @get '/tx/multisig.js', browserify '../client/tx/multisig.coffee'

  @get '/arbitrate/new.js', browserify '../client/arbitrate/new.coffee'
  @get '/arbitrate/manage.js', browserify '../client/arbitrate/manage.coffee'

  @get '/', (req, res) -> res.render join pages_dir, 'index'
  @get '/*.html', (req, res) -> res.render join pages_dir, req.url.replace /\.html$/, ''
