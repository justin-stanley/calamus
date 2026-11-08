# calamus logo

The mark is a quill: a feather whose bare shaft, the calamus, runs unbroken into a cut nib. It sits
beside [FeatherReader](https://github.com/justin-stanley/feather-reader)'s feather and uses
FeatherReader's colours.

| file | use |
|---|---|
| `calamus-lockup-light.svg`, `calamus-lockup-dark.svg` | mark and name, for light and dark backgrounds (the README header) |
| `calamus-mark-light.svg`, `calamus-mark-dark.svg` | the mark alone, transparent |
| `calamus-icon.svg`, `calamus-icon-512.png`, `apple-touch-icon.png` | the mark on its dark tile |
| `favicon.svg`, `favicon-16.png`, `favicon-32.png` | favicon: no nib slit (it muddies below 48 px), slightly larger in its tile |
| `social-preview.svg`, `social-preview.png` | GitHub's social preview, 1280×640 |

## Colours

| | hex | where |
|---|---|---|
| spruce | `#3e6459` | the mark on light backgrounds (FeatherReader's light accent) |
| sage | `#93bfb2` | the mark on dark backgrounds (FeatherReader's dark accent) |
| ink | `#191714` | the dark ground |
| paper | `#faf8f3` | the light ground |

## Type

The name is set in **Charis SIL Bold**, the open-licensed descendant of Charter (FeatherReader's
serif), and converted to outlines, so it renders the same everywhere with no font. Charis SIL is
© SIL International, under the [SIL Open Font License 1.1](https://openfontlicense.org).

## Rebuilding

Every file is generated from one path definition (`build/mark.py`, the mark drawn upright on a
64-unit grid from a width profile, then turned 45°), so the variants can't drift apart:

```sh
python3 -m pip install fonttools   # and rsvg-convert, from librsvg
python3 assets/build/build.py      # writes into assets/; fetches the font subset from Google Fonts
```

The logo is licensed with the rest of the repository (AGPL-3.0-only).
