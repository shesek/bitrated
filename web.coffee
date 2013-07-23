{ readdirSync } = require 'fs'
{ basename, join } = require 'path'

stylus = require 'stylus'
express = require 'express'
browserify = do (browserify = require 'browserify-middleware') ->
  (path) -> browserify path, transform: [ 'coffeeify', 'jadeify2' ]


module.exports = express().configure ->
  @set 'view engine', 'jade'
  @set 'views', join __dirname, 'views'
  @set 'public', join __dirname, 'public'

  @locals.tip_address = '1D9LYFxYK5ktANk2xRhtBV41koL4YDYsRS'

  @use express.favicon()
  @use express.logger 'dev'
  @use @router

  @use stylus.middleware src: (join __dirname, 'stylus'), dest: @settings.public
  @use express.static @settings.public

  @get '/tx.js', browserify 'client/tx/index.coffee'
  @get '/arbitrate.js', browserify 'client/arbitrate.coffee'

  @get '/', (req, res) -> res.render 'index'
  @get '/*.html', (req, res) -> res.render basename req.url, '.html'
