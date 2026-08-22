import argparse
import sys
from pathlib import Path

from app.engine import ARFAEngine


def main():
    parser = argparse.ArgumentParser(
        description="ARFA Python AI Engine - Vulnerability Analysis & Correlation Pipeline"
    )

    parser.add_argument(
        "--input",
        "-i",
        type=str,
        required=True,
        help="Path to ARFA Go Scanner JSON results",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="report.json",
        help="Path to write output FinalReport JSON",
    )

    parser.add_argument(
        "--llm-url",
        type=str,
        default=None,
        help="Optional Ollama/LLM API base URL",
    )

    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.is_file():
        sys.stderr.write(
            f"Error: Input file not found: {args.input}\n"
        )
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        raw_content = f.read()

    engine = ARFAEngine(llm_url=args.llm_url)
    report = engine.process(raw_content)

    output_json = report.model_dump_json(indent=2)

    output_path = Path(args.output)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(output_json)

    print(
        f"[+] Analysis successfully written to "
        f"{output_path.resolve()}"
    )
    print(
        f"    Total findings processed : "
        f"{report.metadata.input_findings_count}"
    )
    print(
        f"    Unique findings          : "
        f"{report.metadata.deduplicated_count}"
    )
    print(
        f"    Security Posture Score   : "
        f"{report.executive_summary.overall_posture_score}/100"
    )


if __name__ == "__main__":
    main()
