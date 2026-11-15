"""
Real traffic volumes: hourly vehicles per toll plaza on the state highways granted to
concessionaires in São Paulo (ARTESP open data, "volume pedagiado horário", 2026).

A toll plaza with a gantry is the closest public proxy for an ALPR camera: every vehicle
that crosses it is registered, per hour and per direction. Here each (plaza, direction)
plays one camera of the Nêmesis, and its hourly count is the n of a search window.

Building the compact file (needs pandas, run once; the raw CSVs are ~1.7 GB):

    python -m simulation.tolls build ~/Downloads/volume_horario_2026

writes simulation/data/pedagio_2026_horario.csv.gz: one line per camera with its hourly
counts from 2026-01-01 00h onwards. Loading it (load()) needs only the standard library.
"""
import csv
import gzip
import io
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

DATA_FILE = Path(__file__).resolve().parent / "data" / "pedagio_2026_horario.csv.gz"
START = datetime(2026, 1, 1)
KEY_COLUMNS = ["DATA", "HORA", "LOTE", "PRACA", "SENTIDO"]
TEXT_COLUMNS = KEY_COLUMNS + ["TIPO_CABINE", "TIPO_PASSAGEM", "TP_PAGAMENTO"]
SOURCE = "ARTESP, volume pedagiado horário 2026 (dados abertos)"


@dataclass
class TollCamera:
    id: int
    lot: str
    plaza: str
    direction: str
    hourly: list[int] = field(repr=False)  # vehicles per hour since START

    @property
    def name(self) -> str:
        return f"{self.plaza} ({self.direction})"

    def total(self) -> int:
        return sum(self.hourly)


@dataclass
class TollData:
    cameras: list[TollCamera]
    hours: int

    def instant(self, hour_index: int) -> datetime:
        return START + timedelta(hours=hour_index)

    def hour_index(self, when: datetime) -> int:
        return int((when - START).total_seconds() // 3600)

    def last_day(self) -> str:
        """Last day with any traffic (the files stop mid-year)."""
        last = max((max((i for i, v in enumerate(c.hourly) if v), default=0) for c in self.cameras), default=0)
        return self.instant(last).date().isoformat()


_cache: Optional[TollData] = None


def available() -> bool:
    return DATA_FILE.exists()


def load() -> TollData:
    global _cache
    if _cache is None:
        cameras = []
        with gzip.open(DATA_FILE, "rt", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            next(reader)  # header
            for row in reader:
                camera_id, lot, plaza, direction, counts = row
                cameras.append(TollCamera(int(camera_id), lot, plaza, direction, [int(v) for v in counts.split()]))
        hours = max(len(c.hourly) for c in cameras) if cameras else 0
        _cache = TollData(cameras=cameras, hours=hours)
    return _cache


def build(folder: str) -> None:
    """Aggregates the raw ARTESP CSVs into DATA_FILE (pandas needed only here)."""
    import pandas as pd

    totals: dict[tuple, dict[int, int]] = {}
    files = sorted(Path(folder).expanduser().glob("VOLUME_PEDAGIADO-*-HORARIO-2026.csv"))
    if not files:
        raise SystemExit(f"no VOLUME_PEDAGIADO-*-HORARIO-2026.csv in {folder}")
    rows_read = 0
    for path in files:
        for chunk in pd.read_csv(path, chunksize=400_000, dtype={c: str for c in TEXT_COLUMNS}, low_memory=False):
            vehicles = chunk.drop(columns=[c for c in TEXT_COLUMNS if c in chunk.columns])
            chunk = chunk[KEY_COLUMNS].copy()
            chunk["V"] = vehicles.apply(pd.to_numeric, errors="coerce").fillna(0).sum(axis=1).astype("int64")
            chunk["H"] = ((pd.to_datetime(chunk["DATA"]) - pd.Timestamp(START)).dt.days * 24
                          + pd.to_numeric(chunk["HORA"]).astype(int))
            grouped = chunk.groupby(["LOTE", "PRACA", "SENTIDO", "H"])["V"].sum()
            for (lot, plaza, direction, hour), value in grouped.items():
                bucket = totals.setdefault((lot.strip(), plaza.strip(), direction.strip()), {})
                bucket[int(hour)] = bucket.get(int(hour), 0) + int(value)
            rows_read += len(chunk)
        print(f"  {path.name}: {rows_read:,} linhas lidas até aqui", flush=True)

    hours = max(max(b) for b in totals.values()) + 1
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(DATA_FILE, "wt", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "lote", "praca", "sentido", "veiculos_por_hora"])
        for camera_id, key in enumerate(sorted(totals)):
            bucket = totals[key]
            writer.writerow([camera_id, *key, " ".join(str(bucket.get(h, 0)) for h in range(hours))])
    print(f"-> {DATA_FILE} ({len(totals)} câmeras/sentidos, {hours} horas)")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "build":
        build(sys.argv[2])
    else:
        print(__doc__)
