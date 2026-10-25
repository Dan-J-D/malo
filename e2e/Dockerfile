# Headless runner for the desktop app: Xvfb + WebKitWebDriver + tauri-driver + Selenium.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-0 webkit2gtk-driver libgtk-3-0 libayatana-appindicator3-1 librsvg2-common \
      xvfb xauth dbus-x11 fonts-dejavu-core ca-certificates curl python3 python3-selenium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
# Testing only: the system browser is replaced by a script that signs in to the mock OAuth provider.
COPY fake-browser.sh /usr/local/bin/xdg-open
