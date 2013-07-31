express = require 'express'
mongoose = require 'mongoose'
ext_type = require 'connect-ext-type'
{ createServer } = require 'http'
{ join } = require 'path'

module.exports = express().configure ->
  @set 'port', process.env.PORT or 8070
  @set 'view engine', 'jade'
  @set 'views', join __dirname, 'views'
  @locals
    url: process.env.URL or "http://localhost:#{@settings.port}/"
    pubkey_address: process.env.PUBKEY_ADDRESS

  @db = mongoose.connect process.env.MONGO_URI or 'mongodb://localhost/'
  @models = require('./models')(@db)

  @use express.favicon()
  @use express.logger 'dev'
  @use express.bodyParser()
  @use express.methodOverride()
  @use ext_type '.json': 'application/json', '.txt': 'text/plain'

  server = createServer this
  require('./websocket').call(this, server)
  require('./assets').call(this) if @settings.env is 'development'
  # assets are pre-compiled and served by nginx on production

  @use '/u', require('./user')(this)

  server.listen @settings.port, => console.log "Listening on #{@settings.port}"
