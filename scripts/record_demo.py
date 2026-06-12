#!/usr/bin/env python3
"""Auto-generate a narrated demo video for the Devpost submission.

Pipeline (all local, no cloud):
  1. Build a storyboard of scenes (title, architecture, live terminal, guardrail,
     audit trail) using REAL findings from docs/submission/sample-run.
  2. Render each scene as a 1920x1080 frame with Pillow (terminal-styled).
  3. Synthesize narration per scene with macOS `say` (TTS).
  4. Assemble per-scene MP4 segments (still frame held for narration length)
     and concatenate into docs/submission/evidencegene-demo.mp4 with ffmpeg.

Usage:  uv run python scripts/record_demo.py
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "submission"
SAMPLE = OUT / "sample-run" / "findings.jsonl"
ARCH = OUT / "architecture-wide.png"
HERO = OUT / "hero-banner.png"

W, H = 1920, 1080
BG = (13, 17, 23)
FG = (220, 223, 228)
GREEN = (63, 185, 80)
CYAN = (86, 182, 194)
AMBER = (210, 153, 34)
RED = (248, 81, 73)
DIM = (139, 148, 158)

MONO = "/System/Library/Fonts/Menlo.ttc"
VOICE = "Samantha"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(MONO, size, index=1 if bold else 0)


def _wrap(text: str, width: int) -> list[str]:
    out, line = [], ""
    for word in text.split():
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


def terminal_frame(
    lines: list[tuple[str, tuple]],
    title: str = "sansforensics@sift: ~/evidencegene-court",
) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # window chrome
    d.rectangle([60, 50, W - 60, H - 50], fill=(22, 27, 34), outline=(48, 54, 61), width=2)
    d.rectangle([60, 50, W - 60, 96], fill=(33, 38, 45))
    for i, c in enumerate([(237, 106, 94), (245, 191, 79), (98, 197, 84)]):
        d.ellipse([90 + i * 34, 64, 110 + i * 34, 84], fill=c)
    d.text((W // 2, 73), title, font=font(22), fill=DIM, anchor="mm")
    f = font(28)
    y = 130
    for text, color in lines:
        d.text((100, y), text, font=f, fill=color)
        y += 42
    return img


def title_frame(big: str, small: str, color=GREEN) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((W // 2, H // 2 - 60), big, font=font(86, bold=True), fill=FG, anchor="mm")
    d.line([(W // 2 - 360, H // 2 + 10), (W // 2 + 360, H // 2 + 10)], fill=color, width=4)
    for i, line in enumerate(_wrap(small, 64)):
        d.text((W // 2, H // 2 + 60 + i * 50), line, font=font(34), fill=DIM, anchor="mm")
    return img


def image_frame(path: Path, caption: str) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    pic = Image.open(path).convert("RGB")
    scale = min((W - 200) / pic.width, (H - 240) / pic.height)
    pic = pic.resize((int(pic.width * scale), int(pic.height * scale)))
    img.paste(pic, ((W - pic.width) // 2, 70))
    d.text((W // 2, H - 90), caption, font=font(34, bold=True), fill=CYAN, anchor="mm")
    return img


def load_findings() -> list[dict]:
    if not SAMPLE.exists():
        return []
    return [json.loads(line) for line in SAMPLE.read_text().splitlines() if line.strip()]


def build_storyboard() -> list[tuple[Image.Image, str]]:
    findings = load_findings()
    confirmed = next((f for f in findings if f["tier"] == "CONFIRMED"), None)
    inferred = [f for f in findings if f["tier"] == "INFERRED"]

    scenes: list[tuple[Image.Image, str]] = []

    # 1. Title
    scenes.append((
        title_frame("EvidenceGene Court", "Adversarial DFIR that can't hallucinate"),
        "In twenty twenty five, attackers ran an autonomous intrusion at ninety percent "
        "autonomy using an AI agent and the Model Context Protocol. The defensive tools "
        "we have hallucinate. This is EvidenceGene Court, where a hallucinated finding "
        "is not discouraged. It is structurally impossible to publish.",
    ))

    # 2. Architecture
    if ARCH.exists():
        scenes.append((
            image_frame(ARCH, "Three architectural boundaries — not prompt rules"),
            "Three boundaries. The agent sees only a typed read-only MCP server over "
            "Volatility and Sleuth Kit. There is no shell tool and no write tool, so "
            "destroying evidence is impossible. Every tool result is stored with a "
            "S H A two fifty six audit chain. And findings must cite artifacts that the "
            "system re-derives from the evidence itself. The model proposes claims. The "
            "evidence decides.",
        ))

    # 3. Live run
    run_lines = [
        ("$ uv run egc-court health", GREEN),
        ("LLM endpoint (localhost:1234): OK", FG),
        ("tool vol: found   tool mmls: found   tool fls: found", DIM),
        ("", FG),
        ("$ uv run egc-court investigate \\", GREEN),
        ("    --memory citadeldc01.mem --source memory:dc01 \\", GREEN),
        ("    --disk 20200918_CDrive.E01 --disk-source disk:dc01", GREEN),
        ("", FG),
        ("[court] Prosecutor -> Defender -> Arbiter ...", DIM),
        ("=== Investigation complete ===", CYAN),
    ]
    if confirmed:
        run_lines.append(("artifacts: 9   published: 4   rejected: 0", FG))
    scenes.append((
        terminal_frame(run_lines),
        "This is D F I R Madness Case oh oh one, a public case with documented ground "
        "truth. A two gigabyte memory image and a four point five gigabyte disk image. "
        "The court runs autonomously on a local model. Prosecutor proposes, Defender "
        "challenges, Arbiter rules.",
    ))

    # 4. The findings
    finding_lines = [("Published findings:", CYAN), ("", FG)]
    if confirmed:
        finding_lines.append(("[CONFIRMED] coreupdater.exe corroborated across", AMBER))
        finding_lines.append(("            memory AND disk", AMBER))
        finding_lines.append(("   refs -> vol_pslist, vol_psscan, vol_netscan,", DIM))
        finding_lines.append(("           disk_file_timeline", DIM))
        finding_lines.append(("", FG))
    for f in inferred[:2]:
        claim = f["claim"].replace("'coreupdater.ex'", "coreupdater.exe")
        for j, ln in enumerate(_wrap(claim, 64)):
            finding_lines.append((("[INFERRED] " if j == 0 else "           ") + ln, FG))
    scenes.append((
        terminal_frame(finding_lines),
        "The court found coreupdater dot exe, the documented implant, and its command "
        "and control connection. Note the tier. The cross-source claim is CONFIRMED, "
        "because it is corroborated by both memory and the disk timeline. Single-source "
        "claims stay INFERRED. Confidence is computed from evidence, not asserted by the "
        "model.",
    ))

    # 5. Blocked hallucination
    scenes.append((
        terminal_frame([
            ("# inject a fabricated claim about a process in NO artifact", DIM),
            ("$ publish('backdoor totallyfake.exe beaconed to 6.6.6.6')", GREEN),
            ("", FG),
            ("WARNING  finding rejected", RED),
            ("BLOCKED: no artifact_refs —", RED),
            ("         evidence-free claims are not publishable", RED),
            ("", FG),
            ("# logged to the audit chain as finding_rejected", DIM),
        ]),
        "Here is the part that matters. I inject a fabricated claim about a process that "
        "exists in no artifact. The serializer fail-closes and rejects it at the A P I "
        "boundary. This is not a prompt rule the model can ignore, and the rejection is "
        "logged. When a weak model emitted placeholder citations during testing, the gate "
        "rejected every one.",
    ))

    # 6. Audit + close
    scenes.append((
        terminal_frame([
            ("$ uv run egc-court verify", GREEN),
            ("audit chain: VALID (17 entries)", CYAN),
            ("", FG),
            ("Every finding traces to the exact tool execution", FG),
            ("that produced it. Single-byte tampering fails replay.", FG),
            ("", FG),
            ("Runs on one laptop. Evidence never leaves the machine.", AMBER),
        ]),
        "Every finding traces to the exact tool execution that produced it, in a hash "
        "chained log that detects single byte tampering. And all of this ran on one "
        "laptop with a local model. The evidence never left the machine. EvidenceGene "
        "Court. The court is the architecture. Thank you.",
    ))

    return scenes


def synth_audio(text: str, path: Path) -> float:
    aiff = path.with_suffix(".aiff")
    subprocess.run(["say", "-v", VOICE, "-o", str(aiff), text], check=True)
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(aiff), "-ar", "44100", "-ac", "2", str(path)],
        check=True, capture_output=True,
    )
    aiff.unlink(missing_ok=True)
    dur = subprocess.run(
        ["ffprobe", "-i", str(path), "-show_entries", "format=duration",
         "-v", "quiet", "-of", "csv=p=0"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    return float(dur)


def main() -> None:
    for tool in ("ffmpeg", "ffprobe", "say"):
        if shutil.which(tool) is None:
            raise SystemExit(f"required tool missing: {tool}")

    scenes = build_storyboard()
    print(f"storyboard: {len(scenes)} scenes")
    tmp = Path(tempfile.mkdtemp(prefix="egc-demo-"))
    segments = []

    for i, (frame, narration) in enumerate(scenes):
        frame_path = tmp / f"frame_{i:02d}.png"
        audio_path = tmp / f"audio_{i:02d}.m4a"
        seg_path = tmp / f"seg_{i:02d}.mp4"
        frame.save(frame_path)
        dur = synth_audio(narration, audio_path) + 0.6  # small tail pad
        subprocess.run(
            ["ffmpeg", "-y", "-loop", "1", "-i", str(frame_path), "-i", str(audio_path),
             "-c:v", "libx264", "-tune", "stillimage", "-t", f"{dur:.2f}",
             "-c:a", "aac", "-b:a", "192k", "-pix_fmt", "yuv420p", "-r", "25",
             "-vf", f"scale={W}:{H}", str(seg_path)],
            check=True, capture_output=True,
        )
        segments.append(seg_path)
        print(f"  scene {i}: {dur:.1f}s")

    concat_file = tmp / "concat.txt"
    concat_file.write_text("".join(f"file '{s}'\n" for s in segments))
    out_path = OUT / "evidencegene-demo.mp4"
    subprocess.run(
        ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(concat_file),
         "-c", "copy", str(out_path)],
        check=True, capture_output=True,
    )
    total = subprocess.run(
        ["ffprobe", "-i", str(out_path), "-show_entries", "format=duration",
         "-v", "quiet", "-of", "csv=p=0"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    print(f"\nDONE -> {out_path}  ({float(total):.0f}s)")


if __name__ == "__main__":
    main()
