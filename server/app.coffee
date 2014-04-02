express = require 'express'
mongoose = require 'mongoose'
ext_type = require 'connect-ext-type'
{ createServer } = require 'http'
{ join } = require 'path'

module.exports = express().configure ->
  @set 'port', process.env.PORT or 8070
  @set 'host', process.env.HOST or '127.0.0.1'
  @set 'view engine', 'jade'
  @set 'views', join __dirname, 'views'
  @set 'url', process.env.URL or "http://localhost:#{@settings.port}/"
  @enable 'trust proxy' if process.env.PROXIED

  @locals
    url: @settings.url
    ver: process.env.VER or ''
    testnet: !!process.env.TESTNET
    testnet_api: process.env.TESTNET_API
    pretty: @settings.env is 'development'

  @db = mongoose.connect process.env.MONGO_URI or 'mongodb://localhost/'
  @db.set 'debug', true if @settings.env is 'development'
  @models = require('./models')(@db)

  @use express.favicon()
  @use express.logger 'dev'
  @use express.json()
  @use express.urlencoded()
  @use express.methodOverride()
  @use ext_type '.json': 'application/json', '.txt': 'text/plain'

  server = createServer this
  require('./websocket').call(this, server)
  require('./assets').call(this) if (@settings.env is 'development') or process.env.SERVE_ASSETS
  @use express.static process.env.STATIC_PATH if process.env.STATIC_PATH
  # assets are pre-compiled and served by nginx on production

  @use '/u', require('./user')(this)

  server.listen @settings.port, @settings.host, => console.log "Listening on #{@settings.host}:#{@settings.port}"
