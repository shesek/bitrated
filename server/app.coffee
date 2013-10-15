express = require 'express'
mongoose = require 'mongoose'
ext_type = require 'connect-ext-type'
{ createServer } = require 'http'
{ join } = require 'path'

module.exports = express().configure ->
  @set 'port', process.env.PORT or 8070
  @set 'view engine', 'jade'
  @set 'views', join __dirname, 'views'
  @set 'url', process.env.URL or "http://localhost:#{@settings.port}/"
  @locals
    url: @settings.url
    pubkey_address: process.env.PUBKEY_ADDRESS
    pretty: @settings.env is 'development'

  @db = mongoose.connect process.env.MONGO_URI or 'mongodb://localhost/'
  @models = require('./models')(@db)

  @use express.basicAuth 'u2', 'b1tr4t3d'
  @use express.favicon()
  @use express.logger 'dev'
  @use express.bodyParser()
  @use express.methodOverride()
  @use ext_type '.json': 'application/json', '.txt': 'text/plain'

  server = createServer this
  require('./websocket').call(this, server)
  require('./assets').call(this) if (@settings.env is 'development') or process.env.SERVE_ASSETS
  # assets are pre-compiled and served by nginx on production

  @use '/u', require('./user')(this)

  server.listen @settings.port, => console.log "Listening on #{@settings.port}"
