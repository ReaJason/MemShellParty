<h1 align="center">MemShellParty</h1>

<p align="center"><a href="../README.md">中文</a> | English<br></p>


<div align="center">

[![release](https://img.shields.io/github/v/release/reajason/memshellparty?label=Release&style=flat-square)](https://github.com/ReaJason/MemShellParty/releases)
[![MavenCentral](https://img.shields.io/maven-central/v/io.github.reajason/generator?label=MavenCentral&style=flat-square)](https://central.sonatype.com/artifact/io.github.reajason/generator)
[![docker-pulls](https://img.shields.io/docker/pulls/reajason/memshell-party?label=DockerHub%20Pulls&style=flat-square)](https://hub.docker.com/r/reajason/memshell-party)
</div>
<div align="center">

[![Telegram](https://img.shields.io/badge/Chat-Telegram-%2326A5E4?style=flat-square&logo=telegram&logoColor=%2326A5E4)](https://t.me/memshell)
[![OnlinePartyWebSite](https://img.shields.io/badge/WebSite-OnlineParty-%23646CFF?style=flat-square&logo=vite&logoColor=%23646CFF)](https://party.mem.mk)
</div>

> [!WARNING]
> This tool is intended only for security researchers, network administrators, and related technical personnel for authorized security testing, vulnerability assessment, and security auditing. Using this tool for any unauthorized network attack or penetration test is illegal, and users must bear the corresponding legal responsibility.

> [!TIP]
> Since I mainly work on security product development and do not have practical offensive experience, please feel free to open an issue or join the Telegram group if you have questions about usage, implementation, or adaptation requests. You are welcome to learn and exchange ideas together.

MemShellParty is a fast memshell generation tool focused on mainstream web middleware. It is designed to simplify the workflow of security researchers and red team members, improving offensive and defensive efficiency.

<p align="center">
  <img src="../assets/normal_memshell.png" alt="normal_memshell" width="24%">
  <img src="../assets/agent_memshell.png" alt="agent_memshell" width="24%">
  <img src="../assets/dnslog_probe.png" alt="dnslog_probe" width="24%">
  <img src="../assets/about_page.png" alt="about_page" width="24%">
</p>

## Key Features

- **Non-intrusive**: Generated memshells do not affect normal target middleware traffic, even when more than a dozen different memshells are injected at the same time.
- **Strong compatibility**: Covers common middleware and frameworks in offensive and defensive scenarios, and supports JDK6 through JDK21.
- **High availability**: A comprehensive automated test matrix has been built for all supported middleware and frameworks, ensuring each generated payload has high usability and stability while reducing uncertainty in real-world use.
- **Extremely lightweight**: Through deeply optimized bytecode generation strategies, MemShellParty greatly reduces memshell size compared with traditional tools such as JMG. Regular memshells are reduced by **30%**, and Agent memshells are reduced by **80%** using ASM.
- **One-click simplicity**: Built-in payload generation is provided for common vulnerabilities such as expression injection, deserialization, and SSTI. The system automatically configures Java module restriction bypasses and dynamically generates the optimal attack payload, enabling one-click generation for common vulnerability payloads.
- **High flexibility**: Natively supports common memshell capabilities such as Godzilla, Behinder, AntSword, Suo5, and NeoreGeorg. With the highly flexible custom memshell upload feature, any customized payload can be integrated into the MemShellParty generation system to build an attack platform that best fits your tactical needs.

## Quick Start

### Read Before Use

[Compatibility](https://party.mem.mk/ui/docs/compatibility) helps you understand MemShellParty's adaptation status for each service, so you can choose the right service type for different applications.

The probe memshell maps detected service types one by one. The detected service type is the service type that can be used to generate memshells. This is not necessarily the middleware type. For example, Apusic10 is detected as GlassFish because it is developed based on GlassFish.

### Online Site

> Only for users who want to try it out. Please use caution with other publicly exposed services, as generated memshells may contain backdoors.

You can access the master branch at [https://party.mem.mk](https://party.mem.mk). The latest image is automatically deployed for each release.

For features under development, you can try the dev branch early at [https://dev-party.mem.mk](https://dev-party.mem.mk).

### Local Deployment (Recommended)

> Suitable for quick internal network or local deployment. Starting the service directly with Docker is fast and convenient.

After deploying with Docker, access http://127.0.0.1:8080

```bash
# Pull the latest image from Docker Hub
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party reajason/memshell-party:latest

# Pull the latest image from Github Container Registry
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party ghcr.io/reajason/memshell-party:latest

# Poor network quality? Use the Nanjing University Github Container Registry mirror
docker run --pull=always --rm -it -d -p 8080:8080 --name memshell-party ghcr.nju.edu.cn/reajason/memshell-party:latest
```

## Special Thanks

- [vulhub/java-chains](https://github.com/vulhub/java-chains)
- [pen4uin/java-memshell-generator](https://github.com/pen4uin/java-memshell-generator)
- [pen4uin/java-echo-generator](https://github.com/pen4uin/java-echo-generator)

### Let's start the party 🎉
