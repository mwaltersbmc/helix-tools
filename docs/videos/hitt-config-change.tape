Output docs/assets/videos/hitt-config-change.mp4
Output docs/assets/videos/hitt-config-change.gif

Source "docs/videos/_settings.tape"

Hide
Type "cd docs/videos/demo && cp -f sample-hitt.conf hitt.conf && chmod +x hitt.sh"
Enter
Show

Type "# Change HITT configuration (hitt-config-change)"
Enter
Sleep 500ms
Type "# Option 1: show current hitt.conf"
Enter
Type "cat hitt.conf"
Enter
Sleep 2s

Type "# Option 2: delete config and re-run setup"
Enter
Sleep 500ms
Type "rm hitt.conf && bash hitt.sh -m post-hp"
Enter
Sleep 2s
