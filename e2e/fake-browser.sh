#!/bin/sh
# Stand-in for the system browser in the headless GUI test (installed as xdg-open).
# Plays the user on the mock OAuth provider: submits the login form, then follows the
# redirect to Malo's loopback listener with the authorization code. Testing only.
url="$1"
case "$url" in
  http://localhost:18080/*)
    location=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$url" --data-urlencode "username=${MALO_E2E_OAUTH_USER:?}")
    curl -s "$location" >/dev/null
    ;;
  *) echo "fake browser: ignoring $url" >&2 ;;
esac
