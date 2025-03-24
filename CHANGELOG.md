# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.6.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.6.0) - 2025-03-24

### Added

- 支持自定义内存马生成（#49）by @ReaJason
- 支持自动发布 DEV 分支代码 CD

### Changed

- 简化 Jetty 获取 Context 代码
- 优化 Dockerfile 减小镜像体积

**Full Changelog:** [v1.5.0...v1.6.0](https://github.com/ReaJason/MemShellParty/compare/v1.5.0...v1.6.0)

## [v1.5.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.5.0) - 2025-03-01

### Added

- 支持 NeoreGeorg 内存马生成 by @ReaJason
- 支持 UI 显示更新按钮跳转到 GitHub Release 界面

### Changed

- 简化 Valve 内存马代码
- 升级 Gradle 8.13

**Full Changelog:** [v1.4.0...v1.5.0](https://github.com/ReaJason/MemShellParty/compare/v1.4.0...v1.5.0)

## [v1.4.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.4.0) - 2025-02-26

### Added

- 支持缩小字节码 (移除调试信息) by @ReaJason
- 支持 Tomcat Jakarta WebSocket

### Fixed

- 修复自定义注入器类名不起作用

### Changed

- 优化跨平台开发体验，将 bash 脚本改为 js 脚本

**Full Changelog:** [v1.3.2...v1.4.0](https://github.com/ReaJason/MemShellParty/compare/v1.3.2...v1.4.0)

## [v1.3.2](https://github.com/ReaJason/MemShellParty/releases/tag/v1.3.2) - 2025-02-25

### Fixed

- 修复 Tomcat WebSocket 注入报错，无法工作

### Changed

- 添加 foojay-toolchains 插件，支持 Dockerfile 构建时自动下载缺失的 JDK 版本
- 优化构建 Spring Boot 的 Dockerfile，最小权限原则
- 支持一键构建的 Dockerfile，适配需要 NGINX 反代的场景
- 代码重构支持一处注册所有 Server 的 Shell 配置

**Full Changelog:** [v1.3.1...v1.3.2](https://github.com/ReaJason/MemShellParty/compare/v1.3.1...v1.3.2)

## [v1.3.1](https://github.com/ReaJason/MemShellParty/releases/tag/v1.3.1) - 2025-02-20

### Added

- UI 中打包配置中添加 Loading 状态

### Fixed

- 修复 UI 在修改目标服务时，挂载类型有时未跟着变化导致生成失败

**Full Changelog:** [v1.3.0...v1.3.1](https://github.com/ReaJason/MemShellParty/compare/v1.3.0...v1.3.1)

## [v1.3.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.3.0) - 2025-02-20

### Added

- 支持 Hessian、Hessian2 反序列化，XSLT 链 (#36) by @ReaJason

### Changed

- 移除无用依赖，JavaSocket，Gson
- Gradle 升级至 8.12.1
- 更新 TestContainers 和 Junit 的版本

### Fixed

- 修复 UI 在仅修改打包方式重新生成时，多选 payload 下拉框置空，且 payload 没有变为最新的。

**Full Changelog:** [v1.2.1...v1.3.0](https://github.com/ReaJason/MemShellParty/compare/v1.2.1...v1.3.0)

## [v1.2.1](https://github.com/ReaJason/MemShellParty/releases/tag/v1.2.1) - 2025-02-19

### Changed

- UI 增强手机端响应式，增强 i18n 显示 (#39)

### Fixed

- 修复 CB110 版本 serialVersionUID 修改失效导致无法利用成功

**Full Changelog:** [v1.2.0...v1.2.1](https://github.com/ReaJason/MemShellParty/compare/v1.2.0...v1.2.1)

## [v1.2.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.2.0) - 2025-02-19

### Added

- 支持 AntSword 内存马生成 by @ReaJason
- 添加 Java 反序列化其他 CB 版本 Payload 生成

### Changed

- CI 分离单独测试 was7 集成测试，大幅度减少测试时间
- 部分 UI 调整

### Fixed

- 修复随机类名如果为保留字时会无法加载

**Full Changelog:** [v1.1.0...v1.2.0](https://github.com/ReaJason/MemShellParty/compare/v1.1.0...v1.2.0)

## [v1.1.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.1.0) - 2025-02-15

### Added

- 支持 Suo5 内存马生成 by @ReaJason

### Changed

- 升级 TailWind CSS v4
- 分离 i18n EN 和 ZH 为两个 json 文件，方便维护以及 VSCode 插件识别

### Fixed

- 修复 sonner 颜色主题未随着修改而变化
- 修复 IDEA 本地构建 version 一直是 unspecified

**Full Changelog:** [v1.0.0...v1.1.0](https://github.com/ReaJason/MemShellParty/compare/v1.0.0...v1.1.0)

## [v1.0.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.0.0) - 2025-01-03

### Added

- 支持 Tomcat、Jetty、WebLogic、GlassFish、JBoss、Resin 等 18 个中间件或框架的应用内存马
- 支持 Filter、Servlet、Listener、NettyHandler、Agent 等常见内存马挂载类型
- 支持哥斯拉、冰蝎、命令执行功能
- 支持 Base64、Jar、JSP、常见表达式、常见模板引擎、反序列化等打包方式