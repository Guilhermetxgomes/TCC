"""
Experiments behind the "Implementação e resultados experimentais" chapter.
No database needed: everything runs in memory on the real crypto code.

    python -m experiments.cap4 e1      # unit cost of the puzzle (both solver strategies)
    python -m experiments.cap4 e2      # cost and size of a capture on the camera
    python -m experiments.cap4 e3      # window cost vs. camera volume: per record, per block, two-level
    python -m experiments.cap4 e4      # Busca Total: cost of the committee operations
    python -m experiments.cap4 e5      # targeted search vs. mass surveillance (extrapolation)
    python -m experiments.cap4 e6      # the same attacks against a conventional backend and the Nêmesis
    python -m experiments.cap4 e7      # real hourly volumes of the São Paulo toll plazas (ARTESP)
    python -m experiments.cap4 all

Each experiment writes experiments/resultados/<name>.csv; e3 and e5 also write a
.png when matplotlib is installed. Measured numbers depend on the machine and on
this Python implementation: the hardware-independent unit is the number of
attempts, and every time/US$ column is derived from it.
"""
import csv
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

from crypto import p256, threshold
from crypto.block_crumpling import solve_block
from crypto.escrow import CameraEscrow, open_with_session_key
from crypto.puzzle import solve_puzzle
from services.camera import Camera
from services.committee import EmergencyCommittee, Scope
from simulation.costs import AWS_HOURLY_PRICE_USD

OUT = Path(__file__).resolve().parent / "resultados"
AWS_VCPUS = 4  # m7g.xlarge
SERIES = {  # label, colour, marker, line style (identity never rests on colour alone)
    "registro": ("por registro (N)", "#2a78d6", "o", "-"),
    "bloco": ("por bloco ($N_B$)", "#eb6834", "s", "--"),
    "hibrido": ("dois níveis ($N_B$ e $N$)", "#1baf7a", "^", "-."),
}


def write_csv(name: str, rows: list[dict]) -> None:
    OUT.mkdir(exist_ok=True)
    path = OUT / f"{name}.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"-> {path.relative_to(Path.cwd()) if path.is_relative_to(Path.cwd()) else path}")
    for row in rows:
        print("   " + " | ".join(f"{key}={value}" for key, value in row.items()))


def stamp(index: int, per_hour: int, hour: int = 8) -> str:
    """Evenly spaced capture times inside one hour of 2026-01-01."""
    second = index * 3600 // max(per_hour, 1)
    return f"2026-01-01T{hour:02d}:{second // 60:02d}:{second % 60:02d}+00:00"


def plate(rng: random.Random) -> str:
    return "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=3)) + f"{rng.randrange(10_000):04d}"


def seconds_per_attempt(attempts_target: int = 200_000) -> float:
    camera = Camera(id=1, location_id=1, puzzle_level=attempts_target)
    attempts, elapsed = 0, 0.0
    while attempts < attempts_target:
        solved = solve_puzzle(camera.encrypt_plate("ABC1D23"))
        attempts += solved["attempts"]
        elapsed += solved["elapsed_seconds"]
    return elapsed / attempts


# ---------------------------------------------------------------------------------------
# E1 -- unit cost of the puzzle
# ---------------------------------------------------------------------------------------

def e1(levels=((1_000, 300), (10_000, 100), (100_000, 30))) -> None:
    rows = []
    for n, repetitions in levels:
        camera = Camera(id=1, location_id=1, puzzle_level=n)
        for sequential in (False, True):
            attempts, seconds = [], 0.0
            for _ in range(repetitions):
                solved = solve_puzzle(camera.encrypt_plate("ABC1D23"), sequential=sequential)
                attempts.append(solved["attempts"])
                seconds += solved["elapsed_seconds"]
            rows.append({
                "N": n,
                "solver": "sequencial" if sequential else "com_reposicao",
                "repeticoes": repetitions,
                "tentativas_media": round(statistics.mean(attempts), 1),
                "tentativas_esperadas": (n + 1) / 2 if sequential else n,
                "tentativas_desvio": round(statistics.stdev(attempts), 1),
                "tentativas_max": max(attempts),
                "us_por_tentativa": round(seconds / sum(attempts) * 1e6, 3),
            })
    write_csv("e1_puzzle", rows)


# ---------------------------------------------------------------------------------------
# E2 -- what a capture costs on the camera
# ---------------------------------------------------------------------------------------

def e2(captures: int = 3000) -> None:
    committee = EmergencyCommittee(4, 8)
    committee.public_key("2026-01")  # key generation is not the camera's cost
    modes = {
        "por_registro": dict(puzzle_level=10_000_000),
        "por_bloco": dict(puzzle_level=1, block_level=10_000_000_000),
        "dois_niveis": dict(puzzle_level=5_000_000, block_level=5_000_000_000),
    }
    rng = random.Random(1)
    plates = [plate(rng) for _ in range(captures)]
    rows = []
    for mode, params in modes.items():
        for with_escrow in (False, True):
            escrow = CameraEscrow(1, committee.public_key) if with_escrow else None
            camera = Camera(id=1, location_id=1, escrow=escrow, **params)
            camera.encrypt_plate(plates[0], stamp(0, captures))  # opens the block/session: measured apart
            headers, wraps = camera.drain_block_headers(), camera.drain_session_wraps()
            started = time.perf_counter()
            records = [camera.encrypt_plate(p, stamp(i, captures)) for i, p in enumerate(plates)]
            elapsed = time.perf_counter() - started
            record = records[0]
            rows.append({
                "esquema": mode,
                "custodia_busca_total": "sim" if with_escrow else "nao",
                "us_por_captura": round(elapsed / captures * 1e6, 1),
                "bytes_por_registro": len(record.c_prime) + len(record.nonce) + len(record.ciphertext)
                + len(record.signature or b""),
                "bytes_por_bloco": sum(len(h.c_prime) + len(h.check_nonce) + len(h.check_tag) for h in headers),
                "bytes_por_sessao": sum(len(w.r) + len(w.nonce) + len(w.wrapped) for w in wraps),
            })
    started = time.perf_counter()
    for day in range(1, 21):  # one new session (key wrap) per day
        CameraEscrow(1, committee.public_key).session_key(f"2026-01-{day:02d}T08:00:00+00:00")
    rows_extra = [{"operacao": "abrir sessão na câmera (embrulhar chave)", "ms": round((time.perf_counter() - started) / 20 * 1e3, 2)}]
    write_csv("e2_captura", rows)
    write_csv("e2_sessao", rows_extra)


# ---------------------------------------------------------------------------------------
# E3 -- cost of opening a one-hour window vs. the camera's volume
# ---------------------------------------------------------------------------------------

def scheme_params(n: int, reference_volume: int) -> dict:
    """The three schemes, calibrated to cost the same on a camera with `reference_volume` records/hour."""
    return {
        "registro": dict(puzzle_level=n),
        "bloco": dict(puzzle_level=1, block_level=reference_volume * n),
        "hibrido": dict(puzzle_level=n // 2, block_level=reference_volume * n // 2),
    }


def expected_window(scheme: dict, volume: int, opened_fraction: float = 1.0) -> float:
    """
    Expected attempts to open `opened_fraction` of a one-hour window with the sequential
    solver (the rational adversary): a puzzle of size x costs (x + 1) / 2 on average.
    """
    block = (scheme["block_level"] + 1) / 2 if "block_level" in scheme else 0
    return block + opened_fraction * volume * (scheme["puzzle_level"] + 1) / 2


def e3(n: int = 50, reference_volume: int = 1000, volumes=(10, 100, 1000, 3000), repetitions: int = 20) -> None:
    """
    Measured with the sequential solver: a block is a single puzzle, and with the
    with-replacement solver (geometric, standard deviation = mean) a handful of
    repetitions would say little about its mean.
    """
    rng = random.Random(3)
    schemes = scheme_params(n, reference_volume)
    rows = []
    for name, params in schemes.items():
        for volume in volumes:
            open_attempts, closed_attempts, seconds = [], [], []
            for _ in range(repetitions):
                camera = Camera(id=1, location_id=1, block_granularity="hour", **params)
                records = [camera.encrypt_plate(plate(rng), stamp(i, volume)) for i in range(volume)]
                headers = camera.drain_block_headers()
                started = time.perf_counter()
                block_attempts, prefix = 0, b""
                if headers:
                    solved = solve_block(headers[0], sequential=True)
                    block_attempts, prefix = solved["attempts"], solved["key"]
                per_record = [solve_puzzle(record, key_prefix=prefix, sequential=True)["attempts"] for record in records]
                seconds.append(time.perf_counter() - started)
                open_attempts.append(block_attempts + sum(per_record))
                target = rng.randrange(volume)  # busca fechada: stops at the target's record
                closed_attempts.append(block_attempts + sum(per_record[: target + 1]))
            rows.append({
                "esquema": name, "N_registro": params["puzzle_level"], "T_bloco": params.get("block_level", 0),
                "registros_na_hora": volume, "repeticoes": repetitions,
                "aberta_tentativas_media": round(statistics.mean(open_attempts)),
                "aberta_tentativas_esperadas": round(expected_window(params, volume)),
                "fechada_tentativas_media": round(statistics.mean(closed_attempts)),
                "fechada_tentativas_esperadas": round(expected_window(params, volume, (volume + 1) / (2 * volume))),
                "aberta_segundos_media": round(statistics.mean(seconds), 3),
            })
    write_csv("e3_janela_vs_volume", rows)

    # Time of day: the same schemes over a day with very uneven traffic (ILLUSTRATIVE
    # profile, not measured data), analytically, with realistic sizes.
    realistic_n = 10_000_000
    realistic = scheme_params(realistic_n, reference_volume)
    profile = [30, 15, 10, 10, 20, 80, 400, 1500, 3000, 2200, 1200, 1000,
               1100, 1000, 1000, 1100, 1500, 2600, 3000, 1800, 900, 500, 200, 80]
    hourly = []
    for hour, volume in enumerate(profile):
        row = {"hora": hour, "registros": volume}
        for name, params in realistic.items():
            cost = expected_window(params, volume)
            row[f"{name}_tentativas_janela"] = f"{cost:.3e}"
            row[f"{name}_tentativas_por_registro"] = f"{cost / volume:.3e}"
        hourly.append(row)
    write_csv("e3_perfil_diario", hourly)
    plot_e3(rows, hourly, n, reference_volume, realistic_n)


def plot_e3(rows: list[dict], hourly: list[dict], n: int, reference_volume: int, realistic_n: int) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("   (matplotlib not installed: figures skipped)")
        return
    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.edgecolor": "#52514e", "axes.labelcolor": "#0b0b0b", "text.color": "#0b0b0b",
                         "xtick.color": "#52514e", "ytick.color": "#52514e", "grid.color": "#e4e3df"})

    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    for name, (label, colour, marker, style) in SERIES.items():
        points = [row for row in rows if row["esquema"] == name]
        xs = [row["registros_na_hora"] for row in points]
        ax.plot(xs, [row["aberta_tentativas_esperadas"] for row in points], style, color=colour, linewidth=2, label=label)
        ax.plot(xs, [row["aberta_tentativas_media"] for row in points], marker, color=colour, markersize=7,
                markeredgecolor="white", markeredgewidth=1.2, linestyle="none")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("registros da câmera em uma hora")
    ax.set_ylabel("tentativas para abrir a hora inteira")
    ax.set_title(f"Custo da Busca Aberta de 1 h (N = {n}; esquemas igualados em {reference_volume} registros/h)\n"
                 "linhas: valor esperado · marcadores: média medida (solver sequencial)", fontsize=9, loc="left")
    ax.grid(True, which="major", linewidth=0.6)
    ax.legend(frameon=False, loc="lower right")
    fig.tight_layout()
    fig.savefig(OUT / "e3_janela_vs_volume.png", dpi=200)
    plt.close(fig)

    fig, axes = plt.subplots(2, 1, figsize=(6.2, 5.2), sharex=True)
    hours = [row["hora"] for row in hourly]
    for name, (label, colour, marker, style) in SERIES.items():
        axes[0].plot(hours, [float(row[f"{name}_tentativas_janela"]) for row in hourly], style, color=colour,
                     linewidth=2, marker=marker, markersize=4, label=label)
        axes[1].plot(hours, [float(row[f"{name}_tentativas_por_registro"]) for row in hourly], style, color=colour,
                     linewidth=2, marker=marker, markersize=4, label=label)
    axes[0].set_ylabel("tentativas para abrir\na hora inteira")
    axes[1].set_ylabel("tentativas por\nregistro exposto")
    axes[1].set_xlabel("hora do dia (perfil de tráfego ilustrativo)")
    axes[0].set_title(f"Mesma câmera ao longo do dia (N = 10^{len(str(realistic_n)) - 1};\n"
                      f"esquemas igualados em {reference_volume} registros/h)", fontsize=9, loc="left")
    for ax in axes:
        ax.set_yscale("log")
        ax.grid(True, which="major", linewidth=0.6)
    axes[1].set_xticks(range(0, 24, 3))
    fig.legend(*axes[0].get_legend_handles_labels(), frameon=False, ncol=3, loc="lower center")
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(OUT / "e3_perfil_diario.png", dpi=200)
    plt.close(fig)
    print(f"-> figures in {OUT}")


# ---------------------------------------------------------------------------------------
# E4 -- Busca Total: what the committee path costs
# ---------------------------------------------------------------------------------------

def timed_ms(function, repetitions: int) -> float:
    started = time.perf_counter()
    for _ in range(repetitions):
        function()
    return (time.perf_counter() - started) / repetitions * 1e3


def e4(configurations=((2, 3), (4, 8), (8, 15)), repetitions: int = 15, records: int = 3000) -> None:
    rows = []
    for t, n in configurations:
        public, shares = threshold.deal(t, n)
        r_point, key = threshold.encapsulate(public, b"ctx")
        partials = [threshold.partial_decrypt(share, r_point) for share in shares[:t]]
        proof = threshold.prove_partial(shares[0], r_point, partials[0])
        assert threshold.combine(public, r_point, partials, b"ctx") == key
        rows.append({
            "t": t, "n": n,
            "gerar_chave_ms": round(timed_ms(lambda: threshold.deal(t, n), 3), 2),
            "embrulhar_camera_ms": round(timed_ms(lambda: threshold.encapsulate(public, b"ctx"), repetitions), 2),
            "decifragem_parcial_ms": round(timed_ms(lambda: threshold.partial_decrypt(shares[0], r_point), repetitions), 2),
            "prova_ms": round(timed_ms(lambda: threshold.prove_partial(shares[0], r_point, partials[0]), repetitions), 2),
            "verificar_prova_ms": round(timed_ms(lambda: threshold.verify_partial(public, r_point, partials[0], proof), repetitions), 2),
            "combinar_t_parciais_ms": round(timed_ms(lambda: threshold.combine(public, r_point, partials, b"ctx"), repetitions), 2),
            "abrir_1_embrulho_ms": None,
            "shamir_reconstruir_ms": round(timed_ms(lambda: threshold.reconstruct_secret(shares[:t]), repetitions), 3),
            "shamir_abrir_1_embrulho_ms": None,
        })
        secret = threshold.reconstruct_secret(shares[:t])
        rows[-1]["shamir_abrir_1_embrulho_ms"] = round(
            timed_ms(lambda: threshold.decapsulate(secret, r_point, b"ctx"), repetitions), 2)
        rows[-1]["abrir_1_embrulho_ms"] = round(
            t * rows[-1]["decifragem_parcial_ms"] + rows[-1]["combinar_t_parciais_ms"], 2)
    write_csv("e4_comite", rows)

    # Once a session key is open: records per second through the escrow path.
    committee = EmergencyCommittee(4, 8)
    rng = random.Random(4)
    rows = []
    for mode, params in (("por_registro", dict(puzzle_level=10_000_000)),
                         ("por_bloco", dict(puzzle_level=1, block_level=10_000_000_000))):
        camera = Camera(id=1, location_id=1, escrow=CameraEscrow(1, committee.public_key), **params)
        captured = [camera.encrypt_plate(plate(rng), stamp(i, records)) for i in range(records)]
        headers = {h.block: h for h in camera.drain_block_headers()}
        started = time.perf_counter()
        keys = committee.open_session_keys(Scope(period="2026-01"), camera.drain_session_wraps(), [1, 2, 3, 4])
        committee_seconds = time.perf_counter() - started
        session_key = keys[(1, "2026-01-01")]
        started = time.perf_counter()
        for record in captured:
            open_with_session_key(record, session_key, headers.get(record.block))
        elapsed = time.perf_counter() - started
        rows.append({
            "esquema": mode, "registros": records, "quorum_ms_por_camera_sessao": round(committee_seconds * 1e3, 1),
            "us_por_registro": round(elapsed / records * 1e6, 1), "registros_por_segundo": round(records / elapsed),
        })
    write_csv("e4_busca_total_vazao", rows)


# ---------------------------------------------------------------------------------------
# E5 -- targeted search vs. mass surveillance (extrapolation from the measured unit cost)
# ---------------------------------------------------------------------------------------

def openssl_rate(algorithm: str, block_bytes: int):
    """Operations per second of one primitive, from `openssl speed` (None if unavailable)."""
    try:
        output = subprocess.run(
            ["openssl", "speed", "-evp", algorithm, "-bytes", str(block_bytes), "-seconds", "1"],
            capture_output=True, text=True, timeout=30,
        ).stdout
        match = re.search(r"([\d.]+)k\s*$", output.strip().splitlines()[-1])
        return float(match.group(1)) * 1000 / block_bytes
    except Exception:
        return None


def e5(cameras: int = 5000, vehicles_per_hour: int = 1000, hours: int = 24 * 365) -> None:
    """
    cameras / vehicles_per_hour are WORKING ASSUMPTIONS (not validated against CET data).
    A rational adversary scans k sequentially, so each puzzle costs N/2 attempts on average.
    """
    python_spa = seconds_per_attempt()
    profiles = [("python_medido", python_spa)]
    sha, gcm = openssl_rate("sha256", 64), openssl_rate("aes-256-gcm", 16)
    if sha and gcm:
        # Lower bound on a native attempt: one SHA-256 block + one small AES-GCM operation
        # (ignores the AES key schedule), i.e. an optimistic adversary on this same CPU.
        profiles.append(("nativo_estimado_openssl", 1 / sha + 1 / gcm))
        print(f"   openssl speed: sha256(64 B) = {sha:,.0f}/s, aes-256-gcm(16 B) = {gcm:,.0f}/s")
    usd_per_core_second = AWS_HOURLY_PRICE_USD / AWS_VCPUS / 3600
    targeted_records = (vehicles_per_hour + 1) / 2  # busca fechada, 1 camera x 1 hour
    mass_records = cameras * vehicles_per_hour * hours
    rows = []
    for profile, spa in profiles:
        for n in (10**6, 10**7, 10**8, 10**9, 2**31, 10**11):
            per_puzzle = n / 2
            targeted, mass = targeted_records * per_puzzle, mass_records * per_puzzle
            rows.append({
                "perfil": profile, "us_por_tentativa": round(spa * 1e6, 4), "N": n,
                "busca_fechada_1h_tentativas": f"{targeted:.3e}",
                "busca_fechada_1h_nucleo_horas": f"{targeted * spa / 3600:.3e}",
                "busca_fechada_1h_usd": f"{targeted * spa * usd_per_core_second:.3e}",
                "massa_1ano_tentativas": f"{mass:.3e}",
                "massa_1ano_nucleo_anos": f"{mass * spa / (3600 * 24 * 365):.3e}",
                "massa_1ano_usd": f"{mass * spa * usd_per_core_second:.3e}",
            })
    write_csv("e5_dirigida_vs_massa", rows)
    print(f"   hipóteses: {cameras} câmeras x {vehicles_per_hour} veículos/h x {hours} h = {mass_records:.3e} registros; "
          f"US$ {AWS_HOURLY_PRICE_USD}/h por instância de {AWS_VCPUS} vCPUs, usando todas as vCPUs")
    plot_e5(rows)


def plot_e5(rows: list[dict]) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.edgecolor": "#52514e", "xtick.color": "#52514e", "ytick.color": "#52514e",
                         "grid.color": "#e4e3df"})
    profiles = list(dict.fromkeys(row["perfil"] for row in rows))
    fig, axes = plt.subplots(1, len(profiles), figsize=(3.4 * len(profiles), 3.4), sharey=True, squeeze=False)
    for ax, profile in zip(axes[0], profiles):
        points = [row for row in rows if row["perfil"] == profile]
        xs = [row["N"] for row in points]
        ax.plot(xs, [float(row["busca_fechada_1h_usd"]) for row in points], "-o", color="#2a78d6", linewidth=2,
                markersize=5, label="busca fechada: 1 câmera, 1 h")
        ax.plot(xs, [float(row["massa_1ano_usd"]) for row in points], "--s", color="#eb6834", linewidth=2,
                markersize=5, label="varredura: todas as câmeras, 1 ano")
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("N (tamanho do puzzle por registro)")
        ax.set_title(profile.replace("_", " "), fontsize=9, loc="left")
        ax.grid(True, which="major", linewidth=0.6)
    axes[0][0].set_ylabel("custo de computação (US$)")
    axes[0][0].legend(frameon=False, loc="center left", fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "e5_dirigida_vs_massa.png", dpi=200)
    plt.close(fig)


# ---------------------------------------------------------------------------------------
# E6 -- the same attacks against a conventional ALPR backend and against the Nêmesis
# ---------------------------------------------------------------------------------------


def e6(seed: int = 1, budget_seconds: float = 3.0, realistic_n: int = 10**7) -> None:
    """Same simulation as the web UI (seed 1, 120 vehicles); in memory, no Postgres."""
    from simulation import attacks
    from simulation.city_graph import CityGraph
    from simulation.engine import run_simulation
    from simulation.memory_server import MemoryServer
    from simulation.tampering import forge_attack, move_attack

    server = MemoryServer()
    world = run_simulation(CityGraph.load(), server, "e6", n_vehicles=120, ticks=240, puzzle_level=1000,
                           crime_tick=60, seed=seed)
    conv = attacks.ConventionalServer(world)
    rows = []

    dump_conv = attacks.conventional_dump(conv)
    dump_nem = attacks.nemesis_brute_force(server, world, budget_seconds, realistic_n)
    rows.append({"ataque": "ler toda a base", "convencional": f"{dump_conv['records']} placas em "
                 f"{dump_conv['seconds'] * 1000:.2f} ms", "nemesis": f"{dump_nem['opened']} de {dump_nem['records']} "
                 f"em {budget_seconds:.0f} s (N=1000); base inteira com N={realistic_n:.0e}: "
                 f"{dump_nem['full_seconds'] / 3600:.1f} h de um núcleo, US$ {dump_nem['full_usd']:.2f}"})

    innocent = next(v.plate for v in world.vehicles if v.plate != world.crime.plate)
    track_conv = attacks.conventional_track(conv, innocent)
    track_nem = attacks.nemesis_brute_force(server, world, budget_seconds, realistic_n, innocent)
    rows.append({"ataque": "seguir um veículo pela placa", "convencional": f"{track_conv['sightings']} avistamentos "
                 f"em {track_conv['seconds'] * 1000:.3f} ms", "nemesis": f"{track_nem['sightings']} de "
                 f"{track_conv['sightings']} em {budget_seconds:.0f} s (N=1000); todos exigem abrir a base inteira"})

    crime, keys = world.crime, world.camera_keys
    instant = world.clock.iso(crime.tick)
    entry = next(r for r in server.get_rows_in_window("e6", crime.node, instant, instant)
                 if solve_puzzle(r["record"])["plate"] == crime.plate)
    k = solve_puzzle(entry["record"])["k_found"]
    _, move_checks = move_attack(entry["record"], k, b"", keys[crime.node], crime.plate, crime.node + 1,
                                 world.clock.iso(crime.tick + 300))
    _, forge_checks = forge_attack(entry["record"], k, b"", keys[crime.node], "XYZ9Z99")
    for name, checks in (("mudar câmera e instante", move_checks), ("trocar a placa", forge_checks)):
        rows.append({"ataque": name, "convencional": "aceito (UPDATE sem verificação)",
                     "nemesis": "; ".join(f"{c['label']}: {'detecta' if c['detected'] else 'não detecta'}"
                                          for c in checks)})
    write_csv("e6_ataques", rows)


# ---------------------------------------------------------------------------------------
# E7 -- real hourly volumes (ARTESP toll plazas, 2026)
# ---------------------------------------------------------------------------------------


def e7(realistic_n: int = 10**7) -> None:
    from simulation import costs, real_search, tolls

    data = tolls.load()
    hourly = []
    for camera in data.cameras:
        nonzero = [i for i, v in enumerate(camera.hourly) if v]
        hourly += camera.hourly[nonzero[0]:nonzero[-1] + 1] if nonzero else []
    hourly.sort()
    q = lambda p: hourly[int(p * (len(hourly) - 1))]
    means = sorted((c.total() / data.hours for c in data.cameras), reverse=True)
    total = sum(c.total() for c in data.cameras)
    per_year = total * 8760 / data.hours
    spa = seconds_per_attempt()
    busiest = max(data.cameras, key=lambda c: c.total())
    profile = [statistics.mean(busiest.hourly[h::24]) for h in range(24)]
    search = real_search.run(data, busiest, "2026-03-10", 17, 1, 100, realistic_n)
    mass_seconds = per_year * costs.expected_attempts(realistic_n) * spa
    hypothesis = costs.CITY_CAMERAS * costs.CITY_RECORDS_PER_CAMERA_HOUR * costs.CITY_HOURS
    rows = [{
        "cameras": len(data.cameras), "periodo": f"{tolls.START.date()} a {data.last_day()}",
        "passagens": total, "passagens_por_ano": round(per_year), "media_h": round(statistics.mean(hourly), 1),
        "p10_h": q(.1), "mediana_h": q(.5), "p90_h": q(.9), "p99_h": q(.99), "max_h": hourly[-1],
        "cameras_media_ge_1000": sum(m >= 1000 for m in means), "cameras_media_lt_100": sum(m < 100 for m in means),
        "maior_media_h": round(means[0]), "camera_mais_movimentada": busiest.name,
        "pico_sobre_vale_mais_movimentada": round(max(profile) / min(profile), 1),
        "us_por_tentativa": round(spa * 1e6, 3), "N": realistic_n,
        "busca_fechada_pico_usd": round(search["extrapolated"]["fechada"]["usd"], 4),
        "busca_aberta_pico_usd": round(search["extrapolated"]["aberta"]["usd"], 4),
        "n_pico": search["n"],
        "varredura_rede_1ano_nucleo_anos": round(mass_seconds / (86400 * 365)),
        "varredura_rede_1ano_usd": round(costs.cost_usd(mass_seconds)),
        "registros_hipotese_5000x1000": hypothesis, "rede_real_sobre_hipotese": round(per_year / hypothesis, 4),
    }]
    write_csv("e7_dados_reais", rows)
    plot_e7(means, profile, busiest.name)


def plot_e7(means: list[float], profile: list[float], busiest: str) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.edgecolor": "#52514e", "xtick.color": "#52514e", "ytick.color": "#52514e",
                         "grid.color": "#e4e3df"})
    fig, (left, right) = plt.subplots(1, 2, figsize=(7.2, 3.2), gridspec_kw={"width_ratios": [1.3, 1]})
    left.bar(range(1, len(means) + 1), means, width=1.0, color="#2a78d6", linewidth=0)
    left.axhline(1000, color="#0b0b0b", linestyle="--", linewidth=1)
    left.text(len(means), 1060, "hipótese: 1.000 veículos/h", ha="right", va="bottom", fontsize=8, color="#52514e")
    left.set_xlabel("praças e sentidos, em ordem decrescente")
    left.set_ylabel("veículos por hora (média)")
    left.set_xlim(0, len(means) + 1)
    left.grid(True, axis="y", linewidth=0.6)
    left.set_axisbelow(True)
    right.bar(range(24), profile, width=0.8, color="#2a78d6", linewidth=0)
    right.set_xlabel("hora do dia")
    right.set_ylabel("veículos por hora (média)")
    right.set_xticks(range(0, 24, 3))
    right.set_title(busiest.title(), fontsize=8, loc="left", color="#52514e")
    right.grid(True, axis="y", linewidth=0.6)
    right.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(OUT / "e7_volume_real.png", dpi=200)
    plt.close(fig)


EXPERIMENTS = {"e1": e1, "e2": e2, "e3": e3, "e4": e4, "e5": e5, "e6": e6, "e7": e7}

if __name__ == "__main__":
    chosen = sys.argv[1:] or ["all"]
    for name in (EXPERIMENTS if chosen == ["all"] else chosen):
        print(f"=== {name} ===")
        EXPERIMENTS[name]()
