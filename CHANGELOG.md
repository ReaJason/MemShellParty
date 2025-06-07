# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.10.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.10.0) - 2025-06-07

### Added

- 添加新的 JSP 打包方式（直接使用 defineClass 进行注入）(by @zema1 #67)
- 支持 Tomcat 和 JBossAS ProxyValve 内存马（通过动态代理将 StandardPipeline 的第一个 valve 进行包装注入自定义逻辑）

### Fixed

- 修复哥斯拉无法使用最新版连接
- 修复 TongWeb8 Valve 未适配
- 修复移动端 UI 输入框 placeholder 字体过大
- 修复移动端 UI 类名复制按钮超出卡片范围

### Changed

- 修改 Valve 和 Listener 字节码修改时机，改为生成时再进行修改，方便自定义内存马生成
- 合并 memshell 与 memshell-jdk8 模块，方便维护
- UI 使用新的 shadcn/ui 提供的 Zinc 主题配置
- 将所有 Shell 捕获异常从 Exception 改为 Throwable
- 简化 Shell base64 方法代码
- Gradle 更新至 8.14.2
- 参考 [General Gradle Best Practices](https://docs.gradle.org/current/userguide/best_practices_general.html)，将构建脚本改为
  Kotlin DSL

**Full Changelog:** [v1.9.0...v1.10.0](https://github.com/ReaJason/MemShellParty/compare/v1.9.0...v1.10.0)

## [v1.9.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.9.0) - 2025-05-28

### Added

- 支持 TongWeb8 内存马生成 by @ReaJason
- 通过 context 获取 webAppClassLoader，不再依赖 Thread.currentThread().getContextClassLoader()
  为请求线程，参考：[任意类加载环境下注入内存马](https://reajason.eu.org/writing/whichclassloaderforshell/)
- 全面支持使用 ASM 生成 Agent（仅需 92.5 KB），并且可选 JDKAttacher 与 JREAttacher
- 支持命令执行自定义实现类，RuntimeExec or ForkAndExec

### Fixed

- 修复 Apusic Listener 由于 response 获取错误导致不可用
- 修复 Jakarta WebSocket 无法注入

### Changed

- Godzilla WebSocket 默认使用 AES_BASE64 加密器，支持使用 [GzWebsocket](https://github.com/xsshim/GzWebsocket) 插件进行连接。
- Gradle、Web 项目依赖更新
- UI 生成界面默认勾选缩小字节码
- UI 优化手机端选项布局，单行显示每个输入框
- UI 使用紧凑模式，隐藏非常用字段简化操作路径
- 提取公共 Tailwind CSS 类名，简化表单组件代码
- yup 替代 zod 减少打包体积，并将自定义表单验证融合到 react-hook-form 中优化 UX
- 重构 Shell Generator 代码

**Full Changelog:** [v1.8.0...v1.9.0](https://github.com/ReaJason/MemShellParty/compare/v1.8.0...v1.9.0)

## [v1.8.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.8.0) - 2025-05-14

### Added

- 支持普元中间件内存马生成（only 6.5 版本）by @ReaJason（#60）
- 支持哥斯拉 WebSocket 内存马生成与测试
- 添加 Groovy 通用恶意类加载打包方式（用于测试 Jenkins 脚本执行）
- 命令执行支持加密器，双 Base64 测试绕过 WAF 安全设备

### Fixed

- 修复 Jetty 高版本中 ee8 ~ ee10 无法注入（#61）
- 修复 Spring Boot 下类加载的原因导致的 Tomcat/Jetty/Undertow 部分内存马注入失败

### Changed

- 命令执行改为反射调用 forkAndExec 以绕过 RASP（JDK7+）
- 获取所有线程代码改为 `Thread.getAllStackTraces().keySet()`，高版本 JDK 不再需要 bypass module
- 优化 boot 在启动时即触发 Server 的内存马生成注册，加速第一次请求访问

**Full Changelog:** [v1.7.0...v1.8.0](https://github.com/ReaJason/MemShellParty/compare/v1.7.0...v1.8.0)

## [v1.7.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.7.0) - 2025-04-06

### Added

- 支持发布到 MavenCentral，可通过引入依赖使用生成 API by @ReaJason（#41）
- 支持 CC3、CC4 反序列化 payload 打包方式
- 支持随机参数生成与默认选项（#50）

### Changed

- 去除代码混淆相关代码
- 为了更好地在 MavenCentral 展示，重命名部分模块
- 使用 Jackson 代替 Fastjson 降低 boot 打包体积
- 移除 commons-codec 降低 boot 打包体积
- 升级 shadcn/ui 所有 component 代码

**Full Changelog:** [v1.6.0...v1.7.0](https://github.com/ReaJason/MemShellParty/compare/v1.6.0...v1.7.0)

## [v1.6.0](https://github.com/ReaJason/MemShellParty/releases/tag/v1.6.0) - 2025-03-30

> 做代码生成以及代码混淆真是一件需要耐心的事情

### Added

- 支持自定义内存马生成 by @ReaJason（#49）
- 支持命令回显 ASM Agent 内存马 by @ReaJason（#51）
- 支持简易的代码混淆 by @ReaJason（#13）
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