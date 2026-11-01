// Package stroke renders application-owned stroke diagrams from canonical
// KanjiVG/Make Me a Hanzi sources. It never accepts SVGs from browser uploads.
package stroke

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const maxSVGBytes = 1024 * 1024

var palette = []string{"#e11d48", "#2563eb", "#16a34a", "#d97706", "#9333ea", "#0891b2", "#ea580c", "#4f46e5", "#059669", "#c026d3"}

type node struct {
	name     string
	attrs    []xml.Attr
	text     string
	children []*node
}

func (n *node) get(name string) string {
	for _, a := range n.attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n *node) set(name, value string) {
	for i := range n.attrs {
		if n.attrs[i].Name.Local == name {
			n.attrs[i].Value = value
			return
		}
	}
	n.attrs = append(n.attrs, xml.Attr{Name: xml.Name{Local: name}, Value: value})
}

func element(name string, attrs ...string) *node {
	n := &node{name: name}
	for i := 0; i+1 < len(attrs); i += 2 {
		n.set(attrs[i], attrs[i+1])
	}
	return n
}

func walk(n *node, f func(*node)) {
	f(n)
	for _, c := range n.children {
		walk(c, f)
	}
}

var allowedTags = map[string]bool{"svg": true, "g": true, "path": true, "text": true, "tspan": true, "rect": true, "line": true, "circle": true, "ellipse": true, "polygon": true, "polyline": true, "defs": true, "clipPath": true, "style": true, "title": true, "desc": true}
var allowedAttrs = map[string]bool{"id": true, "class": true, "d": true, "transform": true, "viewBox": true, "width": true, "height": true, "preserveAspectRatio": true, "x": true, "y": true, "x1": true, "x2": true, "y1": true, "y2": true, "rx": true, "ry": true, "cx": true, "cy": true, "r": true, "points": true, "fill": true, "fill-opacity": true, "fill-rule": true, "stroke": true, "stroke-width": true, "stroke-opacity": true, "stroke-linecap": true, "stroke-linejoin": true, "stroke-dasharray": true, "stroke-dashoffset": true, "clip-path": true, "clip-rule": true, "clipPathUnits": true, "style": true, "type": true, "pathLength": true, "font-size": true, "font-family": true, "font-weight": true, "text-anchor": true, "opacity": true, "data-char": true, "data-hex": true}
var localURL = regexp.MustCompile(`(?i)url\(\s*['"]?#[a-z0-9_:.\-]+['"]?\s*\)`)

func safeStyle(s string) bool {
	v := strings.ToLower(s)
	if strings.ContainsAny(v, "\\\x00") {
		return false
	}
	for _, bad := range []string{"@import", "javascript:", "vbscript:", "data:", "expression(", "http:", "https:", "-moz-binding"} {
		if strings.Contains(v, bad) {
			return false
		}
	}
	return !strings.Contains(localURL.ReplaceAllString(v, ""), "url(")
}

// parseSVG permits only the small SVG vocabulary needed by the two upstream
// datasets. DTD/entity expansion, scripts, hyperlinks and external resources are
// never copied to output. Malformed XML fails closed, without a regex fallback.
func parseSVG(data []byte) (*node, error) {
	if len(data) == 0 || len(data) > maxSVGBytes {
		return nil, errors.New("invalid SVG size")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	var root *node
	var stack []*node
	depth, nodes := 0, 0
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid SVG XML")
		}
		switch v := t.(type) {
		case xml.StartElement:
			depth++
			nodes++
			if depth > 80 || nodes > 20000 {
				return nil, errors.New("SVG is too complex")
			}
			if root != nil && len(stack) == 0 {
				return nil, errors.New("multiple SVG roots")
			}
			if !allowedTags[v.Name.Local] {
				return nil, fmt.Errorf("unsupported SVG element %s", v.Name.Local)
			}
			if v.Name.Space != "" && v.Name.Space != "http://www.w3.org/2000/svg" {
				return nil, errors.New("invalid SVG namespace")
			}
			n := element(v.Name.Local)
			for _, a := range v.Attr {
				if a.Name.Space != "" || a.Name.Local == "xmlns" {
					continue
				}
				if !allowedAttrs[a.Name.Local] {
					continue
				}
				if !safeStyle(a.Value) {
					return nil, errors.New("unsafe SVG attribute")
				}
				n.attrs = append(n.attrs, xml.Attr{Name: xml.Name{Local: a.Name.Local}, Value: a.Value})
			}
			if len(stack) == 0 {
				if n.name != "svg" {
					return nil, errors.New("SVG root required")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			depth--
			if len(stack) == 0 {
				return nil, errors.New("unbalanced SVG")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				n := stack[len(stack)-1]
				if n.name == "style" || n.name == "text" || n.name == "tspan" || n.name == "title" || n.name == "desc" {
					n.text += string(v)
				}
			}
		case xml.Directive:
			// The canonical KanjiVG SVG includes a public DOCTYPE. The Go XML
			// decoder does not resolve it, and it is never emitted again.
		}
	}
	if root == nil || depth != 0 {
		return nil, errors.New("missing SVG root")
	}
	var unsafe bool
	walk(root, func(n *node) {
		if n.name == "style" && !safeStyle(n.text) {
			unsafe = true
		}
	})
	if unsafe {
		return nil, errors.New("unsafe SVG style")
	}
	return root, nil
}

func writeNode(e *xml.Encoder, n *node) error {
	a := append([]xml.Attr{}, n.attrs...)
	if n.name == "svg" {
		a = append(a, xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: "http://www.w3.org/2000/svg"})
	}
	s := xml.StartElement{Name: xml.Name{Local: n.name}, Attr: a}
	if err := e.EncodeToken(s); err != nil {
		return err
	}
	if n.text != "" {
		if err := e.EncodeToken(xml.CharData(n.text)); err != nil {
			return err
		}
	}
	for _, c := range n.children {
		if err := writeNode(e, c); err != nil {
			return err
		}
	}
	return e.EncodeToken(s.End())
}

// Normalize applies the same palette, grids and animation timing used by
// dataset_builder.py, preserving canonical stroke paths and number transforms.
func Normalize(raw []byte, charHex string) ([]byte, error) {
	root, err := parseSVG(raw)
	if err != nil {
		return nil, err
	}
	pathCount := 0
	walk(root, func(n *node) {
		if n.name == "path" && strings.TrimSpace(n.get("d")) != "" {
			pathCount++
		}
	})
	if pathCount == 0 {
		return nil, errors.New("canonical stroke paths required")
	}
	mmah := false
	walk(root, func(n *node) {
		if n.get("class") == "flama-grid-box" || (n.name == "style" && (strings.Contains(n.text, "make-me-a-hanzi") || strings.Contains(n.text, "keyframes0") || strings.Contains(n.text, "mmah-"+charHex+"-kf-"))) {
			mmah = true
		}
	})
	if mmah {
		normalizeMMAH(root, charHex)
	} else {
		normalizeKVG(root)
	}
	if root.get("viewBox") == "" {
		root.set("viewBox", "0 0 109 109")
	}
	root.set("width", "100%")
	root.set("height", "100%")
	root.set("preserveAspectRatio", "xMidYMid meet")
	if !strings.Contains(root.get("class"), "flama-stroke-char") {
		root.set("class", strings.TrimSpace("flama-stroke-char "+root.get("class")))
	}
	children := root.children[:0]
	for _, c := range root.children {
		if c.get("id") != "flama-stroke-attribution" {
			children = append(children, c)
		}
	}
	root.children = children
	attribution := element("desc", "id", "flama-stroke-attribution")
	if mmah {
		attribution.text = "Stroke paths from Make Me a Hanzi (https://github.com/skishore/makemeahanzi), derived from Arphic PL KaitiM GB and Arphic PL UKai. Arphic Public License: https://github.com/skishore/makemeahanzi/tree/master/APL . Grid, palette and animation adapted by Flama."
	} else {
		attribution.text = "Stroke paths from KanjiVG (https://kanjivg.tagaini.net/), copyright Ulrich Apel and contributors. This adapted SVG is licensed under Creative Commons Attribution-ShareAlike 3.0: https://creativecommons.org/licenses/by-sa/3.0/ . Grid, palette and animation adapted by Flama."
	}
	root.children = append(root.children, attribution)
	var b bytes.Buffer
	e := xml.NewEncoder(&b)
	if err := writeNode(e, root); err != nil {
		return nil, err
	}
	if err := e.Flush(); err != nil {
		return nil, err
	}
	if b.Len() > maxSVGBytes {
		return nil, errors.New("generated SVG exceeds limit")
	}
	return b.Bytes(), nil
}

func normalizeKVG(root *node) {
	children := root.children[:0]
	for _, c := range root.children {
		if c.name != "style" && c.get("class") != "flama-kvg-bg-layer" {
			children = append(children, c)
		}
	}
	root.children = children
	var paths, texts []*node
	walk(root, func(n *node) {
		if n.name == "path" && n.get("d") != "" && n.get("class") != "flama-kvg-bg" {
			paths = append(paths, n)
		} else if n.name == "text" {
			texts = append(texts, n)
		}
	})
	if len(paths) == 0 {
		return
	}
	css := []string{"/* Flama Sequential Stroke Order Animation (Single Run) & Multi-color Styling */", ":root {", "  --flama-stroke-width: 3.2px;", "  --flama-grid-color: #f1f5f9;", "  --flama-ghost-color: #e2e8f0;"}
	for i, c := range palette {
		css = append(css, fmt.Sprintf("  --flama-stroke-c%d: %s;", i+1, c))
	}
	css = append(css, "}", "@keyframes flama-kanjivg-dash {", "  0% { stroke-dashoffset: 100; opacity: 0.15; }", "  20% { opacity: 1; }", "  100% { stroke-dashoffset: 0; opacity: 1; }", "}", ".flama-kvg-bg { stroke: var(--flama-ghost-color, #e2e8f0); stroke-width: var(--flama-stroke-width, 3.2px); fill: none; stroke-linecap: round; stroke-linejoin: round; }", ".flama-kvg-stroke { fill: none; stroke-linecap: round; stroke-linejoin: round; }", ".flama-kvg-num { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; font-weight: 800; paint-order: stroke fill; stroke: #ffffff; stroke-width: 2px; stroke-linejoin: round; }")
	bg := element("g", "class", "flama-kvg-bg-layer", "fill", "none")
	bg.children = append(bg.children, element("rect", "x", "2", "y", "2", "width", "105", "height", "105", "stroke", "#cbd5e1", "stroke-width", "0.8", "stroke-opacity", "0.7", "rx", "4"), element("path", "d", "M 0 54.5 L 109 54.5 M 54.5 0 L 54.5 109 M 0 0 L 109 109 M 109 0 L 0 109", "stroke", "#e2e8f0", "stroke-width", "0.6", "stroke-dasharray", "2,2", "stroke-opacity", "0.8", "fill", "none"))
	for i, p := range paths {
		bg.children = append(bg.children, element("path", "d", p.get("d"), "class", "flama-kvg-bg"))
		color := fmt.Sprintf("var(--flama-stroke-c%d, %s)", i%len(palette)+1, palette[i%len(palette)])
		p.set("class", fmt.Sprintf("flama-kvg-stroke flama-kvg-s%d", i+1))
		p.set("pathLength", "100")
		p.set("stroke-dasharray", "100")
		p.set("stroke-dashoffset", "100")
		p.set("style", fmt.Sprintf("stroke: %s; stroke-width: var(--flama-stroke-width, 3.2px); animation: flama-kanjivg-dash 0.45s cubic-bezier(0.4, 0, 0.2, 1) %.2fs 1 forwards;", color, float64(i)*0.45))
	}
	for i, t := range texts {
		color := fmt.Sprintf("var(--flama-stroke-c%d, %s)", i%len(palette)+1, palette[i%len(palette)])
		t.set("class", fmt.Sprintf("flama-kvg-num flama-kvg-n%d", i+1))
		t.set("style", fmt.Sprintf("fill: %s; fill-opacity: 0.95; paint-order: stroke fill; stroke: #ffffff; stroke-width: 2px;", color))
	}
	style := element("style", "type", "text/css")
	style.text = "\n" + strings.Join(css, "\n") + "\n"
	root.children = append([]*node{style, bg}, root.children...)
}

var keyframeRE = regexp.MustCompile(`\bkeyframes(\d+)\b`)
var animationIDRE = regexp.MustCompile(`-animation-(\d+)$`)
var startPointRE = regexp.MustCompile(`^M\s*([0-9.\-]+)\s+([0-9.\-]+)`)

func normalizeMMAH(root *node, charHex string) {
	prefix := "mmah-" + charHex
	var numbers []*node
	walk(root, func(n *node) {
		for i := range n.attrs {
			if n.attrs[i].Name.Local == "id" || n.attrs[i].Name.Local == "clip-path" {
				n.attrs[i].Value = strings.ReplaceAll(n.attrs[i].Value, "make-me-a-hanzi-", prefix+"-")
			}
		}
		if n.name == "style" {
			n.text = strings.ReplaceAll(n.text, "make-me-a-hanzi-", prefix+"-")
			n.text = keyframeRE.ReplaceAllString(n.text, prefix+"-kf-${1}")
		}
		if n.name == "path" {
			m := animationIDRE.FindStringSubmatch(n.get("id"))
			xy := startPointRE.FindStringSubmatch(strings.TrimSpace(n.get("d")))
			if len(m) > 1 && len(xy) > 2 {
				i, _ := strconv.Atoi(m[1])
				x, _ := strconv.ParseFloat(xy[1], 64)
				y, _ := strconv.ParseFloat(xy[2], 64)
				t := element("text", "x", fmt.Sprintf("%.0f", math.Max(24, math.Min(980, x-18))), "y", fmt.Sprintf("%.0f", math.Max(48, math.Min(980, 900-y-12))), "fill", palette[i%len(palette)], "fill-opacity", "0.95", "class", fmt.Sprintf("flama-stroke-num flama-sn-%d", i+1))
				t.text = strconv.Itoa(i + 1)
				numbers = append(numbers, t)
			}
		}
	})
	children := root.children[:0]
	for _, c := range root.children {
		if c.get("stroke") != "lightgray" && c.get("class") != "flama-grid-box" && c.get("class") != "flama-mmah-numbers" {
			children = append(children, c)
		}
	}
	root.children = children
	grid := element("g", "class", "flama-grid-box", "fill", "none")
	grid.children = append(grid.children, element("rect", "x", "8", "y", "8", "width", "1008", "height", "1008", "stroke", "#cbd5e1", "stroke-width", "3", "stroke-opacity", "0.7", "rx", "24"), element("path", "d", "M 0 512 L 1024 512 M 512 0 L 512 1024 M 0 0 L 1024 1024 M 1024 0 L 0 1024", "stroke", "#e2e8f0", "stroke-width", "2.5", "stroke-dasharray", "10,10", "stroke-opacity", "0.8"))
	root.children = append([]*node{grid}, root.children...)
	if len(numbers) > 0 {
		sort.SliceStable(numbers, func(i, j int) bool {
			a, _ := strconv.Atoi(numbers[i].text)
			b, _ := strconv.Atoi(numbers[j].text)
			return a < b
		})
		g := element("g", "class", "flama-mmah-numbers", "style", "font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 900; font-size: 56px; paint-order: stroke fill; stroke: #ffffff; stroke-width: 10px; stroke-linejoin: round;")
		g.children = numbers
		root.children = append(root.children, g)
	}
}
