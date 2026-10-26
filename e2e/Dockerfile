# Headless runner for the desktop app: Xvfb + WebKitWebDriver + tauri-driver + Selenium.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-0 webkit2gtk-driver libgtk-3-0 libayatana-appindicator3-1 librsvg2-common \
      xvfb xauth dbus-x11 fonts-dejavu-core ca-certificates curl python3 python3-selenium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
# Testing only: the system browser is replaced by a script that signs in to the mock OAuth provider.
COPY fake-browser.sh /usr/local/bin/xdg-open
