"""
Baixa a malha viária da Cidade Universitária (USP, Butantã) do OpenStreetMap e grava
simulation/data/city.json: vértices = cruzamentos (cada um com uma câmera) e arestas
dirigidas com a probabilidade de um carro escolhê-las a partir do vértice de origem.

É o ÚNICO ponto que usa osmnx (requirements-osm.txt). A simulação lê só o JSON gerado.

    pip install -r requirements-osm.txt
    python scripts/download_city.py
"""
import json
import os
import random
import sys
from pathlib import Path

import networkx as nx
import osmnx as ox

# Cidade Universitária Armando de Salles Oliveira (norte, sul, leste, oeste).
BBOX = {"north": -23.5535, "south": -23.5720, "east": -46.7170, "west": -46.7465}
CONSOLIDATION_TOLERANCE_M = 25  # funde cruzamentos próximos (rotatórias, pistas duplas)
GRAPH_SEED = 42  # fixa as probabilidades de transição

# Peso relativo por tipo de via: vias maiores atraem mais tráfego.
HIGHWAY_WEIGHT = {
    "primary": 3.0, "primary_link": 2.0,
    "secondary": 2.5, "secondary_link": 1.8,
    "tertiary": 2.0, "tertiary_link": 1.5,
    "residential": 1.0, "unclassified": 1.0, "living_street": 0.6, "service": 0.5,
}

OUTPUT = Path(__file__).resolve().parent.parent / "simulation" / "data" / "city.json"


def _first(value):
    return value[0] if isinstance(value, list) else value


def main() -> int:
    if os.environ.get("OVERPASS_ENDPOINT"):  # o servidor público às vezes está lotado
        ox.settings.overpass_endpoint = os.environ["OVERPASS_ENDPOINT"]
    print("Baixando malha viária do OpenStreetMap...")
    graph = ox.graph_from_bbox(
        bbox=(BBOX["west"], BBOX["south"], BBOX["east"], BBOX["north"]), network_type="drive"
    )
    graph = ox.project_graph(graph)
    graph = ox.consolidate_intersections(
        graph, tolerance=CONSOLIDATION_TOLERANCE_M, rebuild_graph=True, dead_ends=False
    )
    graph = ox.project_graph(graph, to_crs="EPSG:4326")  # x = lon, y = lat

    # Colapsa arestas paralelas (mantém a mais curta) e remove laços.
    edges: dict[tuple, dict] = {}
    for u, v, data in graph.edges(data=True):
        if u == v:
            continue
        length = float(data.get("length", 0.0)) or 1.0
        current = edges.get((u, v))
        if current is None or length < current["length"]:
            edges[(u, v)] = {
                "length": length,
                "highway": _first(data.get("highway", "residential")),
                "name": _first(data.get("name", "")) or "",
            }

    simple = nx.DiGraph()
    simple.add_nodes_from((n, graph.nodes[n]) for n in graph.nodes)
    simple.add_edges_from((u, v, attrs) for (u, v), attrs in edges.items())
    largest = max(nx.strongly_connected_components(simple), key=len)
    simple = simple.subgraph(largest).copy()
    print(f"{simple.number_of_nodes()} vértices, {simple.number_of_edges()} arestas (maior componente fortemente conexa)")

    node_ids = {old: new for new, old in enumerate(sorted(simple.nodes))}
    rng = random.Random(GRAPH_SEED)

    nodes = []
    for old, new in node_ids.items():
        street_names = sorted({d["name"] for _, _, d in simple.edges(old, data=True) if d["name"]}
                              | {d["name"] for _, _, d in simple.in_edges(old, data=True) if d["name"]})
        nodes.append({
            "id": new,
            "lat": round(simple.nodes[old]["y"], 6),
            "lon": round(simple.nodes[old]["x"], 6),
            "name": " / ".join(street_names[:2]) or f"Cruzamento {new}",
        })

    out_edges = []
    for old in sorted(simple.nodes):
        successors = sorted(simple.successors(old))
        weights = []
        for succ in successors:
            attrs = simple.edges[old, succ]
            base = HIGHWAY_WEIGHT.get(attrs["highway"], 1.0)
            # gamma(2) = jitter positivo e assimétrico (Dirichlet), reprodutível pela seed
            weights.append(base * rng.gammavariate(2.0, 1.0) / max(attrs["length"], 20.0) ** 0.3)
        total = sum(weights)
        for succ, weight in zip(successors, weights):
            attrs = simple.edges[old, succ]
            out_edges.append({
                "source": node_ids[old],
                "target": node_ids[succ],
                "length": round(attrs["length"], 1),
                "highway": attrs["highway"],
                "name": attrs["name"],
                "p": round(weight / total, 4),
            })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps({"bbox": BBOX, "nodes": nodes, "edges": out_edges}, ensure_ascii=False, indent=1))
    print(f"Gravado em {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
