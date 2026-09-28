# Store screenshots

`01-pair-a-mailbox.png`, `02-what-it-sees.png` — 1280×800, the size Chrome,
Edge and Firefox all accept.

Both frame the **real** built UI (`dist/chrome/options.html`) in an iframe.
Nothing here is a mockup of a screen that does not exist, which matters twice
over: store reviewers reject listings whose screenshots do not match the
product, and a security tool that oversells itself in its own shop window has
already lost the argument.

## Regenerating them

After changing the extension UI, rebuild and re-shoot:

```bash
cd client && npm run build:sensor
cp -r sensor/dist/chrome/* /tmp/shots/ && cp sensor/store/screenshots/shot*.html /tmp/shots/
CH=$(find ~/.cache/hyperframes/chrome -name chrome-headless-shell -type f | head -1)
cd /tmp/shots && for n in 1 2; do "$CH" --headless --disable-gpu --hide-scrollbars \
  --window-size=1280,800 --screenshot=shot$n.png "file://$PWD/shot$n.html"; done
```

The composer files pin the crop with a negative `margin-top` on the iframe, so
if the options page grows a section the offset needs adjusting — check the
output rather than assuming.
