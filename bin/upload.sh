#!/bin/bash
[ -f .env ]  && source .env
[ -z "$NGINX" ] && echo "Usage: NGINX=nginx_directory npm run build-static, or set NGINX in .env" && exit 1

# Push to Github
git push github master

# Get current head commit
HEAD=$(git rev-parse HEAD)

# Build website to www folder
npm run build-static "$NGINX/www"

# Upload changes
cd "$NGINX"
git add -u .
git commit -m "$HEAD"
git push heroku master
