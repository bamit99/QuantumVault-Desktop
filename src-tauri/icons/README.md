# App icons

`icon-source.svg` is the vector master. `icon-source.png` is the rendered 512×512 master.

## Regenerating

ImageMagick's built-in SVG renderer draws gradients as black, so render the SVG with
a Chromium-based browser (Edge is present on Windows) instead:

```bash
msedge --headless=new --disable-gpu --hide-scrollbars \
  --default-background-color=00000000 \
  --screenshot="$PWD/icon-source.png" --window-size=512,512 \
  "file:///$PWD/icon-source.html"

npx tauri icon icon-source.png
```

Then delete the generated `android/` and `ios/` folders if you only ship Windows.
