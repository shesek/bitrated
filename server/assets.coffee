stylus = require 'stylus'
express = require 'express'
{ basename, join } = require 'path'
browserify = do (browserify = require 'browserify-middleware') ->
  (path) -> browserify path, transform: [ 'coffeeify', 'jadeify2' ]


module.exports = ->
  @set 'public', join __dirname, '..', 'public'

  @use stylus.middleware src: @settings.public
  @use express.static @settings.public

  @get '/tx.js', browserify '../client/tx/index.coffee'
  @get '/arbitrate/new.js', browserify '../client/arbitrate/new.coffee'
  @get '/arbitrate/manage.js', browserify '../client/arbitrate/manage.coffee'

  @get '/', (req, res) -> res.render 'index'
  @get '/*.html', (req, res) -> res.render basename req.url, '.html'
