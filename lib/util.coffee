iferr = (errfn, succfn) -> (err, a...) -> if err? then errfn err else succfn a...
extend = (dest, source) -> dest[k]=v for own k, v of source when source[k]?; dest
only = (obj, keys...) ->
  res = {}
  res[key] = obj[key] for key in keys when key of obj
  res

module.exports = { iferr, extend, only }
