Output docs/assets/videos/download-hitt.mp4
Output docs/assets/videos/download-hitt.gif

Source "docs/videos/_settings.tape"

Hide
Type "export REPO_ROOT=$(pwd) && rm -rf /tmp/hitt-download-demo && mkdir -p /tmp/hitt-download-demo && cd /tmp/hitt-download-demo"
Enter
Show

Type "# Download the HITT script (download-hitt)"
Enter
Sleep 500ms
Type "mkdir hitt && cd hitt && curl -skO https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh && chmod a+x hitt.sh"
Enter
Sleep 3s

Hide
Type 'test -x hitt/hitt.sh || (mkdir -p hitt && cp "$REPO_ROOT/hitt/hitt.sh" hitt/hitt.sh && chmod a+x hitt/hitt.sh)'
Enter
Show

Type "ls -la hitt/hitt.sh"
Enter
Sleep 2s
