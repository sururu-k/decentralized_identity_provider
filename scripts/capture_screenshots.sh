#!/bin/bash
set -e

CHROME="/Users/hiro/Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"

cd demo/dist
python3 -m http.server 8089 &
SERVER_PID=$!
cd ../..

sleep 1

"$CHROME" --headless --hide-scrollbars --window-size=1440,900 --screenshot=pic/screenshot_login.png "http://localhost:8089/?step=login"
"$CHROME" --headless --hide-scrollbars --window-size=1440,900 --screenshot=pic/screenshot_consent.png "http://localhost:8089/?step=consent"
"$CHROME" --headless --hide-scrollbars --window-size=1440,900 --screenshot=pic/screenshot_completed.png "http://localhost:8089/?step=completed"
"$CHROME" --headless --hide-scrollbars --window-size=1440,900 --screenshot=pic/screenshot_jwt.png "http://localhost:8089/?step=completed&tab=jwt"

cp pic/screenshot_completed.png pic/demo_ui_screenshot.png

kill $SERVER_PID
echo "Screenshots updated!"
