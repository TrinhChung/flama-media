# Stroke data attribution

The Go worker fetches canonical stroke diagrams at runtime; upstream data is
not vendored in this package. Generated SVGs include a nonvisual attribution
`desc` element and retain the source's applicable license.

- **KanjiVG**: copyright Ulrich Apel and contributors. Stroke data and adapted
  diagrams use [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/).
  [Upstream license and attribution](https://github.com/KanjiVG/kanjivg/blob/master/README.md).
- **Make Me a Hanzi SVGs**: derived from Arphic PL KaitiM GB and Arphic PL UKai,
  governed by the Arphic Public License.
  [Upstream SVG license statement](https://github.com/skishore/makemeahanzi/blob/master/README.md),
  [COPYING](https://github.com/skishore/makemeahanzi/blob/master/COPYING),
  [license texts](https://github.com/skishore/makemeahanzi/tree/master/APL).

Provisioned `STROKE_DATASET_ROOT` files must come from these canonical datasets
and preserve their upstream license files alongside the dataset. The service
does not accept arbitrary uploaded SVGs as stroke sources.
