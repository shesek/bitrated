express = require 'express'
stylus = require 'stylus'
browserify = require 'browserify-middleware'

express().configure ->
  @set 'view engine', 'jade'
  @set 'views', __dirname + '/views'
  @set 'port', process.env.PORT or 8070

  @use express.favicon()
  @use express.logger 'dev'
  @use @router
  if @settings.env is 'development'
    @get '/escrow.js', browserify 'client/escrow.coffee', transform: ['coffeeify', 'jadeify2']
    @use stylus.middleware __dirname + '/public'
  @use express.static __dirname + '/public'

  @get '/', (req, res) -> res.render 'home'
  @get '/escrow', (req, res) -> res.render 'escrow'
  @get '/provider', (req, res) -> res.render 'provider'

  @listen (@get 'port'), => console.log "Running on port #{@get 'port'}"
