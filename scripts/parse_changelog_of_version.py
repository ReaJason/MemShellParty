import argparse
import sys

if __name__ == '__main__':
    capture = False
    result_lines = []
    parser = argparse.ArgumentParser(description="Extract changelog for a specific version")
    parser.add_argument("version", help="The version of the changelog to extract, e.g. 'v1.0.0'")
    args = parser.parse_args()
    version = args.version

    with open("../CHANGELOG.md") as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith(f"## [{version}]"):
                capture = True
            elif capture and line.startswith("## ["):
                break
            elif capture:
                result_lines.append(line)
    if not result_lines:
        print("Specified version not found.", file=sys.stderr)
        sys.exit(1)
    print("".join(result_lines).strip())