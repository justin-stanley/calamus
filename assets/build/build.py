"""Build every calamus logo asset from mark.py and the Charis SIL outlines."""
import os, sys
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.boundsPen import BoundsPen
sys.path.insert(0, os.path.dirname(__file__))
import mark

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPRUCE, SAGE = "#3e6459", "#93bfb2"   # FeatherReader's accent, light and dark
INK, PAPER = "#191714", "#faf8f3"     # FeatherReader's dark and light grounds

FONT_CSS = "https://fonts.googleapis.com/css2?family=Charis+SIL:wght@700&text=calamus"

def charis_bold():
    """Charis SIL Bold (SIL Open Font License 1.1), subset to the word, from
    Google Fonts. Charis is the open descendant of Charter, FeatherReader's serif."""
    import re, urllib.request
    path = os.path.join(OUT, ".charis-bold-subset.ttf")
    if not os.path.exists(path):
        css = urllib.request.urlopen(FONT_CSS).read().decode()
        url = re.search(r"url\((https://fonts\.gstatic\.com/[^)]+)\)", css).group(1)
        urllib.request.urlretrieve(url, path)
    return path

def wordmark(text="calamus"):
    """The word as one path in font units (y up), with its advance and bounds."""
    font = TTFont(charis_bold())
    gs, cmap, hmtx = font.getGlyphSet(), font.getBestCmap(), font["hmtx"]
    upm = font["head"].unitsPerEm
    x, parts, xmin, xmax, ymin, ymax = 0, [], 1e9, -1e9, 1e9, -1e9
    for ch in text:
        g = cmap[ord(ch)]
        pen = SVGPathPen(gs); gs[g].draw(pen)
        b = BoundsPen(gs); gs[g].draw(b)
        if b.bounds:
            x0, y0, x1, y1 = b.bounds
            xmin, xmax, ymin, ymax = min(xmin, x + x0), max(xmax, x + x1), min(ymin, y0), max(ymax, y1)
        parts.append(f'<path transform="translate({x} 0)" d="{pen.getCommands()}"/>')
        x += hmtx[g][0]
    return "".join(parts), upm, (xmin, ymin, xmax, ymax)

def write(name, body):
    with open(os.path.join(OUT, name), "w") as f:
        f.write(body)

# 1. The bare mark, transparent, for light and dark backgrounds.
write("calamus-mark-light.svg", mark.svg(SPRUCE, None))   # for light backgrounds
write("calamus-mark-dark.svg", mark.svg(SAGE, None))      # for dark backgrounds
# 2. The app icon: the mark on FeatherReader's dark ground, rounded square.
write("calamus-icon.svg", mark.svg(SAGE, INK, size=512))
# 3. The favicon: no slit (it muddies below 48 px) and a little larger in its tile.
fav = mark.svg(SAGE, INK, slit=False).replace("scale(1.08)", "scale(1.2)")
write("favicon.svg", fav)

# 4. The lockup: the mark, then the word, baseline-aligned and optically centred.
glyphs, upm, (gx0, gy0, gx1, gy1) = wordmark()
H = 80.0                       # lockup height, in its own units: the mark's tile
word_h = H * 0.46              # the word's ascender-to-baseline height
s = word_h / (gy1 - gy0)       # font units -> lockup units
text_w = (gx1 - gx0) * s
gap = H * 0.03
W = H + gap + text_w + H * 0.06
baseline = (H + word_h) / 2    # centre the word on the mark
def lockup(fg, bg=None):
    rect = f'<rect width="{W:.1f}" height="{H}" fill="{bg}"/>' if bg else ""
    m = (f'<g transform="scale({H/64:.4f})">'
         f'{mark.path_el(fg)}</g>')
    t = (f'<g fill="{fg}" transform="translate({H + gap - gx0 * s:.2f} {baseline:.2f}) scale({s:.5f} {-s:.5f})">'
         f'{glyphs}</g>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W:.1f} {H}" width="{W*4:.0f}" height="{H*4:.0f}" '
            f'role="img" aria-label="calamus"><title>calamus</title>{rect}{m}{t}</svg>\n')
write("calamus-lockup-light.svg", lockup(SPRUCE))
write("calamus-lockup-dark.svg", lockup(SAGE))
# 5. GitHub's social preview (1280x640): the lockup centred on the dark ground,
# at 70% of the width (and never more than 45% of the height).
k = min(1280 * 0.70 / W, 640 * 0.45 / H)
write("social-preview.svg",
      f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 640" width="1280" height="640">'
      f'<rect width="1280" height="640" fill="{INK}"/>'
      f'<g transform="translate({(1280 - W*k)/2:.1f} {(640 - H*k)/2:.1f}) scale({k:.3f})">'
      + lockup(SAGE).split(">", 1)[1].replace("<title>calamus</title>", "").rsplit("</svg>", 1)[0]
      + "</g></svg>\n")
print(f"lockup {W:.1f}x{H}")

# 6. Rasters, for where SVG isn't accepted (needs rsvg-convert from librsvg).
import subprocess
def png(src, dst, width, *extra):
    subprocess.run(["rsvg-convert", "-w", str(width), *extra, os.path.join(OUT, src), "-o", os.path.join(OUT, dst)], check=True)
png("favicon.svg", "favicon-16.png", 16)
png("favicon.svg", "favicon-32.png", 32)
png("calamus-icon.svg", "apple-touch-icon.png", 180)
png("calamus-icon.svg", "calamus-icon-512.png", 512)
png("social-preview.svg", "social-preview.png", 1280)
os.remove(os.path.join(OUT, ".charis-bold-subset.ttf"))
