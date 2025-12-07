import argparse
import sys

if __name__ == '__main__':
    capture = False
    result_lines = []
    parser = argparse.ArgumentParser(description="Extract changelog for a specific version")
    parser.add_argument("version", help="The version of the changelog to extract, e.g. 'v1.0.0'")
    args = parser.parse_args()
    version = args.version

    with open("../../web/content/docs/changelog.mdx") as f:
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
    result_lines.append("## 更新方式\n")
    result_lines.append("### Docker 部署\n")
    result_lines.append("```bash\n")
    result_lines.append("docker rm -f memshell-party\n\n")
    result_lines.append("docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party reajason/memshell-party:latest\n")
    result_lines.append("```\n")
    result_lines.append("### Jar 包启动\n")
    result_lines.append("> 仅支持 JDK17 及以上版本\n")
    result_lines.append("```bash\n")
    result_lines.append(f"java -jar --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED boot-{version.strip('v')}.jar\n")
    result_lines.append("```\n")
    print("".join(result_lines).strip())