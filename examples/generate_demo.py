#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate the repository's original, third-party-free CC0 MP3 demo."""

from __future__ import annotations

import argparse
import math
import os
import shutil
import struct
import subprocess
import tempfile
import wave
from pathlib import Path


SAMPLE_RATE = 44_100
BEAT_SECONDS = 0.34

# An original short motif. MIDI note None is a rest.
MELODY = [
    60, 64, 67, 72, 71, 67, 64, 62,
    60, 64, 69, 67, 65, 64, 62, None,
    55, 60, 64, 67, 69, 67, 64, 60,
    62, 65, 69, 74, 72, 67, 64, 60,
]


def midi_frequency(note: int) -> float:
    return 440.0 * 2.0 ** ((note - 69) / 12.0)


def envelope(position: int, length: int) -> float:
    attack = max(1, int(SAMPLE_RATE * 0.018))
    release = max(1, int(SAMPLE_RATE * 0.055))
    if position < attack:
        return position / attack
    if position >= length - release:
        return max(0.0, (length - position - 1) / release)
    return 1.0


def synthesize_wav(path: Path) -> None:
    note_samples = int(SAMPLE_RATE * BEAT_SECONDS)
    frames = bytearray()
    chord_roots = [48, 45, 53, 55]

    for note_index, note in enumerate(MELODY):
        root = chord_roots[(note_index // 8) % len(chord_roots)]
        melody_hz = midi_frequency(note) if note is not None else 0.0
        bass_hz = midi_frequency(root)
        for sample_index in range(note_samples):
            time_value = sample_index / SAMPLE_RATE
            env = envelope(sample_index, note_samples)
            melody_wave = 0.0
            if note is not None:
                melody_wave = (
                    math.sin(2.0 * math.pi * melody_hz * time_value)
                    + 0.22 * math.sin(4.0 * math.pi * melody_hz * time_value)
                    + 0.08 * math.sin(6.0 * math.pi * melody_hz * time_value)
                )
            bass_wave = 0.32 * math.sin(2.0 * math.pi * bass_hz * time_value)
            pulse = 0.10 * math.sin(2.0 * math.pi * bass_hz * 2.0 * time_value)
            value = max(-1.0, min(1.0, env * (0.46 * melody_wave + bass_wave + pulse)))
            frames.extend(struct.pack("<h", round(value * 32767)))

    with wave.open(str(path), "wb") as target:
        target.setnchannels(1)
        target.setsampwidth(2)
        target.setframerate(SAMPLE_RATE)
        target.writeframes(frames)


def find_ffmpeg(explicit: str | None) -> str:
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            return str(candidate)
        raise SystemExit(f"找不到指定的 FFmpeg：{candidate}")
    discovered = shutil.which("ffmpeg")
    if discovered:
        return discovered
    conda_prefix = os.environ.get("CONDA_PREFIX")
    if conda_prefix:
        candidate = Path(conda_prefix) / "Library" / "bin" / "ffmpeg.exe"
        if candidate.is_file():
            return str(candidate)
    raise SystemExit("找不到 FFmpeg；请先激活包含 ffmpeg 的 Conda 环境")


def main() -> int:
    parser = argparse.ArgumentParser(description="生成原创 CC0 MP3 示例")
    parser.add_argument("--ffmpeg", help="ffmpeg 可执行文件路径")
    args = parser.parse_args()

    output = Path(__file__).resolve().parent / "original_demo.mp3"
    ffmpeg = find_ffmpeg(args.ffmpeg)
    with tempfile.TemporaryDirectory(prefix="kgg-demo-") as temp_dir:
        wav_path = Path(temp_dir) / "original_demo.wav"
        synthesize_wav(wav_path)
        subprocess.run(
            [
                ffmpeg,
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-i",
                str(wav_path),
                "-c:a",
                "libmp3lame",
                "-b:a",
                "192k",
                "-metadata",
                "title=Original Synth Demo",
                "-metadata",
                "artist=KGG to MP3 contributors",
                "-metadata",
                "comment=Generated locally; CC0-1.0; no third-party recording",
                str(output),
            ],
            check=True,
        )
    print(f"已生成：{output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
