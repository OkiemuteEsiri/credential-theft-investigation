import argparse
from pathlib import Path

from .io import load_events
from .investigation import investigate
from .reporting import render_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="Defensive credential-theft investigation correlator")
    parser.add_argument("input", help="Path to synthetic identity-event JSON")
    parser.add_argument("--output", default="reports/generated-assessment.md")
    args = parser.parse_args()

    events = load_events(args.input)
    findings = investigate(events)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(findings), encoding="utf-8")
    print(f"wrote {len(findings)} findings to {output}")


if __name__ == "__main__":
    main()
