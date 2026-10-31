"""The calamus mark, generated from one width profile so every variant agrees.

Drawn upright on a 64-unit grid (vane at the top, nib at the bottom), then
turned 45 degrees clockwise about the centre: vane to the upper right, nib to
the lower left. The shaft runs unbroken into a cut quill nib (no band or
ferrule, which would make it a fountain pen). The vane's cuts follow the barbs,
slanting down toward the shaft, offset between the sides like a real feather.
"""
import math, sys

TOP, VANE_END, NIB_START, TIP = 1.5, 38.5, 52.0, 63.0

def half_width(y):
    if y <= VANE_END:                       # the vane: a slim, pointed leaf
        t = (y - TOP) / (VANE_END - TOP)    # 0 at the tip, 1 where it meets the shaft
        # A pointed tip (t**1.25 keeps the first stretch narrow), widest about
        # 40% of the way down, then easing into the shaft.
        leaf = 6.6 * math.sin(math.pi * min(1.0, t ** 1.25)) ** 0.8
        return max(leaf, 2.35 if t > 0.5 else 0.0)
    if y <= NIB_START:                      # the shaft, tapering slightly
        t = (y - VANE_END) / (NIB_START - VANE_END)
        return 2.35 - 0.45 * t
    t = (y - NIB_START) / (TIP - NIB_START) # the nib: a slight swell, then the cut point
    return 1.9 + 0.75 * math.sin(math.pi * min(t * 1.6, 1) / 2) * (1 - t) ** 0.5 - 1.9 * t ** 1.4

# (y on the edge, depth as a fraction of the half-width, drop toward the shaft)
CUTS = {+1: [(17.0, 0.66, 4.2), (27.0, 0.62, 3.8)], -1: [(21.5, 0.64, 4.2), (28.5, 0.5, 3.2)]}
CUT_GAP = 2.1

def edge(side, slit):
    ys = [TOP + i * 0.25 for i in range(int((TIP - TOP) / 0.25) + 1)]
    pts = []
    cuts = sorted(CUTS[side])
    for y in ys:
        for (cy, depth, drop) in cuts:
            if abs(y - cy) < 0.125:         # insert a slanted V: in, down toward the shaft, and out
                w = half_width(cy)
                pts.append((32 + side * w, cy))
                pts.append((32 + side * w * (1 - depth), cy + drop))
                pts.append((32 + side * half_width(cy + CUT_GAP), cy + CUT_GAP))
        if not any(cy - 0.01 < y < cy + CUT_GAP for (cy, _, _) in cuts):
            pts.append((32 + side * half_width(y), y))
    return pts

def mark_path(slit=True):
    right = edge(+1, slit)
    left = edge(-1, slit)[::-1]
    pts = [(32.0, TOP)] + right + [(32.0, TIP)] + left
    d = "M" + " L".join(f"{x:.2f} {y:.2f}" for x, y in pts) + " Z"
    if slit:                                # the nib's slit, a hole short of the point
        d += " M31.42 60.4 L32.58 60.4 L32.58 55.4 L31.42 55.4 Z"
    return d

def path_el(fg, slit=True, scale=1.08):
    return (f'<path fill="{fg}" fill-rule="evenodd" '
            f'transform="rotate(45 32 32) translate(32 32.5) scale({scale}) translate(-32 -32.5)" '
            f'd="{mark_path(slit)}"/>')

def svg(fg, bg=None, size=64, slit=True, radius=14, title="calamus"):
    rect = f'<rect width="64" height="64" rx="{radius}" fill="{bg}"/>' if bg else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="{size}" height="{size}" '
            f'role="img" aria-label="{title}"><title>{title}</title>{rect}{path_el(fg, slit)}</svg>\n')

if __name__ == "__main__":
    fg = sys.argv[1]; bg = None if len(sys.argv) < 3 or sys.argv[2] == "-" else sys.argv[2]
    print(svg(fg, bg, slit=not (len(sys.argv) > 3 and sys.argv[3] == "noslit")), end="")
