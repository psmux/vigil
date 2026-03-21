#!/usr/bin/env python3
"""
Generate enhanced world map data with country borders.

Downloads Natural Earth GeoJSON data and produces a compact JSON file with:
  - primary:   major coastline polylines (10m resolution)
  - secondary: detail coastline polylines (shorter segments)
  - borders:   country land borders (interior polygon edges shared by 2+ countries)

Output: ../assets/world.json
"""

import json
import math
import os
import time
import urllib.request
import urllib.error
import ssl
from collections import defaultdict

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

URLS = {
    "coastline_10m": (
        "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/"
        "master/geojson/ne_10m_coastline.geojson"
    ),
    "countries_50m": (
        "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/"
        "master/geojson/ne_50m_admin_0_countries.geojson"
    ),
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "..", "assets", "world.json")

# Coordinates are rounded to this many decimal places
DECIMAL_PLACES = 2

# Coastline segments shorter than this (in original points) go into "secondary"
PRIMARY_MIN_POINTS = 20

# Douglas-Peucker simplification tolerance (in degrees).
# ~0.03 degrees is roughly 3 km at the equator -- good balance of detail vs size.
SIMPLIFY_TOLERANCE_PRIMARY = 0.03
SIMPLIFY_TOLERANCE_SECONDARY = 0.05
SIMPLIFY_TOLERANCE_BORDERS = 0.02

# Discard secondary coastlines shorter than this after simplification
SECONDARY_MIN_POINTS = 3

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def perpendicular_distance(point, line_start, line_end):
    """
    Compute the perpendicular distance from *point* to the line segment
    defined by *line_start* and *line_end*.  All inputs are [lon, lat].
    """
    x0, y0 = point
    x1, y1 = line_start
    x2, y2 = line_end
    dx = x2 - x1
    dy = y2 - y1
    denom = math.sqrt(dx * dx + dy * dy)
    if denom == 0:
        return math.sqrt((x0 - x1) ** 2 + (y0 - y1) ** 2)
    return abs(dy * x0 - dx * y0 + x2 * y1 - y2 * x1) / denom


def douglas_peucker(points, tolerance):
    """
    Simplify a polyline using the Douglas-Peucker algorithm (iterative).
    *points* is a list of [lon, lat].  Returns a simplified list.
    """
    n = len(points)
    if n <= 2:
        return list(points)

    # Track which indices to keep
    keep = [False] * n
    keep[0] = True
    keep[n - 1] = True

    # Stack-based iterative approach
    stack = [(0, n - 1)]
    while stack:
        start, end = stack.pop()
        if end - start < 2:
            continue
        max_dist = 0
        max_idx = start
        for i in range(start + 1, end):
            d = perpendicular_distance(points[i], points[start], points[end])
            if d > max_dist:
                max_dist = d
                max_idx = i
        if max_dist > tolerance:
            keep[max_idx] = True
            stack.append((start, max_idx))
            stack.append((max_idx, end))

    return [points[i] for i in range(n) if keep[i]]


def simplify_polyline(points, tolerance):
    """Round, dedupe, then simplify a polyline."""
    rounded = [round_coord(c) for c in points]
    cleaned = dedupe_consecutive(rounded)
    if len(cleaned) <= 2:
        return cleaned
    simplified = douglas_peucker(cleaned, tolerance)
    return dedupe_consecutive(simplified)


def download(url: str, label: str, retries: int = 3, timeout: int = 120) -> dict:
    """Download a URL and parse as JSON, with retries."""
    # Create an SSL context that doesn't verify certificates (needed on some
    # Windows installs where the certificate bundle is incomplete).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for attempt in range(1, retries + 1):
        try:
            print(f"  [{attempt}/{retries}] Downloading {label} ...")
            req = urllib.request.Request(url, headers={"User-Agent": "vigil-map-gen/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read()
                print(f"    -> {len(raw):,} bytes")
                return json.loads(raw)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            print(f"    Error: {exc}")
            if attempt < retries:
                wait = 2 ** attempt
                print(f"    Retrying in {wait}s ...")
                time.sleep(wait)
            else:
                raise SystemExit(f"Failed to download {label} after {retries} attempts.")


def round_coord(coord):
    """Round a [lon, lat] pair to DECIMAL_PLACES."""
    return [round(coord[0], DECIMAL_PLACES), round(coord[1], DECIMAL_PLACES)]


def dedupe_consecutive(ring):
    """Remove consecutive duplicate points from a coordinate ring."""
    if not ring:
        return ring
    out = [ring[0]]
    for pt in ring[1:]:
        if pt != out[-1]:
            out.append(pt)
    return out


def extract_rings_from_geometry(geom):
    """Yield coordinate rings (lists of [lon,lat]) from a GeoJSON geometry."""
    gtype = geom["type"]
    coords = geom["coordinates"]

    if gtype == "Polygon":
        for ring in coords:
            yield ring
    elif gtype == "MultiPolygon":
        for polygon in coords:
            for ring in polygon:
                yield ring
    elif gtype == "LineString":
        yield coords
    elif gtype == "MultiLineString":
        for line in coords:
            yield line


def make_edge_key(a, b):
    """Create a canonical (sorted) key for an edge between two points."""
    # Points are tuples (lon, lat)
    return (min(a, b), max(a, b))


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def process_coastlines(geojson):
    """
    Extract coastline polylines from 10m coastline GeoJSON.
    Returns (primary, secondary) lists of coordinate arrays.
    """
    print("Processing coastlines ...")
    primary = []
    secondary = []

    for feature in geojson["features"]:
        geom = feature.get("geometry")
        if not geom:
            continue
        for ring in extract_rings_from_geometry(geom):
            # Classify by original point count, then simplify
            raw_len = len(ring)
            if raw_len >= PRIMARY_MIN_POINTS:
                simplified = simplify_polyline(ring, SIMPLIFY_TOLERANCE_PRIMARY)
                if len(simplified) >= 2:
                    primary.append(simplified)
            else:
                simplified = simplify_polyline(ring, SIMPLIFY_TOLERANCE_SECONDARY)
                if len(simplified) >= SECONDARY_MIN_POINTS:
                    secondary.append(simplified)

    print(f"  Coastlines: {len(primary)} primary, {len(secondary)} secondary")
    return primary, secondary


def process_borders(geojson):
    """
    Extract land borders from country polygons.

    Strategy: Walk every edge of every country polygon. An edge that appears
    in exactly TWO different countries is a shared land border. Edges that
    appear in only one country are coastlines (or the edge of the dataset)
    and are excluded.

    After identifying border edges, we stitch them into polylines for compact
    output.
    """
    print("Processing country borders ...")

    # Step 1: Collect all edges per country, and count edge usage across countries.
    # edge_key -> set of country indices
    edge_countries = defaultdict(set)

    feature_count = len(geojson["features"])
    for idx, feature in enumerate(geojson["features"]):
        geom = feature.get("geometry")
        if not geom:
            continue
        for ring in extract_rings_from_geometry(geom):
            rounded = [tuple(round_coord(c)) for c in ring]
            cleaned = dedupe_consecutive(rounded)
            for i in range(len(cleaned) - 1):
                key = make_edge_key(cleaned[i], cleaned[i + 1])
                edge_countries[key].add(idx)

    # Step 2: Keep only edges shared by 2+ countries (land borders).
    border_edges = {}
    for key, countries in edge_countries.items():
        if len(countries) >= 2:
            # Store the edge with its original orientation (arbitrary pick)
            border_edges[key] = (key[0], key[1])

    print(f"  Total edges: {len(edge_countries):,}, border edges: {len(border_edges):,}")
    del edge_countries  # free memory

    # Step 3: Stitch edges into polylines.
    # Build adjacency: point -> list of neighboring points (only border edges)
    adjacency = defaultdict(set)
    for (a, b) in border_edges.keys():
        adjacency[a].add(b)
        adjacency[b].add(a)
    del border_edges

    # Walk chains greedily
    visited_edges = set()
    polylines = []

    # Start from degree-1 or degree-3+ nodes first (endpoints), then remaining
    start_candidates = sorted(adjacency.keys(), key=lambda p: (len(adjacency[p]) == 2, p))

    for start in start_candidates:
        for neighbor in list(adjacency[start]):
            edge = make_edge_key(start, neighbor)
            if edge in visited_edges:
                continue
            # Walk a chain
            chain = [start, neighbor]
            visited_edges.add(edge)
            # Continue forward
            cur = neighbor
            prev = start
            while True:
                nexts = [n for n in adjacency[cur] if make_edge_key(cur, n) not in visited_edges]
                if len(nexts) != 1:
                    break  # junction or dead-end
                nxt = nexts[0]
                visited_edges.add(make_edge_key(cur, nxt))
                chain.append(nxt)
                prev = cur
                cur = nxt

            if len(chain) >= 2:
                polylines.append([list(p) for p in chain])

    print(f"  Border polylines: {len(polylines)}")
    return polylines


def main():
    print("=" * 60)
    print("Vigil World Map Data Generator")
    print("=" * 60)

    # Download data
    print("\nStep 1: Downloading GeoJSON data\n")
    coastline_data = download(URLS["coastline_10m"], "10m coastlines")
    countries_data = download(URLS["countries_50m"], "50m countries")

    # Process
    print("\nStep 2: Processing geometries\n")
    primary, secondary = process_coastlines(coastline_data)
    del coastline_data  # free memory

    borders = process_borders(countries_data)
    del countries_data

    # Build output
    output = {
        "primary": primary,
        "secondary": secondary,
        "borders": borders,
    }

    # Write
    print(f"\nStep 3: Writing output to {os.path.abspath(OUTPUT_PATH)}\n")
    os.makedirs(os.path.dirname(os.path.abspath(OUTPUT_PATH)), exist_ok=True)

    # Use separators to minimize whitespace
    json_str = json.dumps(output, separators=(",", ":"))
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(json_str)

    size_bytes = os.path.getsize(OUTPUT_PATH)
    size_mb = size_bytes / (1024 * 1024)
    print(f"  Output size: {size_bytes:,} bytes ({size_mb:.2f} MB)")

    # Summary
    total_points = (
        sum(len(p) for p in primary)
        + sum(len(p) for p in secondary)
        + sum(len(p) for p in borders)
    )
    print(f"\n  Primary coastlines:   {len(primary):>6} polylines")
    print(f"  Secondary coastlines: {len(secondary):>6} polylines")
    print(f"  Country borders:      {len(borders):>6} polylines")
    print(f"  Total points:         {total_points:>6}")
    print(f"\nDone!")


if __name__ == "__main__":
    main()
