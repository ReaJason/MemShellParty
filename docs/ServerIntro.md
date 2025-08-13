# Java 服务简介

以下服务仅我个人遇到的一些场景，与实际攻防场景可能仍有差距，但是在 MemShellParty
中可用于参考进行内存马生成。个别其他服务还请自行辨别其服务类型。如果有其他环境补充，欢迎 PR 交流学习~

## Tomcat

> https://tomcat.apache.org/

Tomcat 使用的是自己 Catalina 模块提供的 Servlets 实现，限制较少，在 MemShellParty 中，服务类型选 Tomcat 即可生成 Tomcat
内存马。

一般而言，SpringWebMVC 项目大多使用 Tomcat 提供 Servlets 容器功能，比如 Nacos，这种情况下可以选择 Tomcat 内存马注入。

其他服务中，致远 OA、Confluence、帆软使用的是 Tomcat。

## Jetty

> https://jetty.org/

Jetty6 版本使用的包名为 `org.mortbay.jetty`，而 7 以上使用的是 `org.eclipse.jetty`，在测试最新的 Jenkins 时，发现 Jetty11+
版本支持 ee8 ~ ee10 的环境，包名对应的是 `org.eclipse.jetty.ee8`，这些在 MemShellParty 中均已支持，因此服务类型选 Jetty
即可生成 Jetty 内存马。

在 SpringWebMVC 项目中也是有可能使用的。

## JBoss

> JBossAS: https://jbossas.jboss.org/downloads

> JBossEAP: https://developers.redhat.com/products/eap/download

JBoss 分为 JBossAS 和 JBossEAP，JBossAS 全版本和 JBossEAP6 使用的 Catalina 模块提供的 Servlets 实现，JBossEAP7 及其以上使用的
[Undertow](https://undertow.io/) 提供的 Servlets 实现。

因此 JBossAS 4~7 以及 JBossEAP6 服务类型选择 JBoss 进行内存马的生成，而 JBossEAP7 服务类型需要选择
Undertow 进行内存马的生成。

## Wildfly

> https://www.wildfly.org/

Wildfly 使用的 [Undertow](https://undertow.io/) 提供的 Servlets 实现，因此服务类型选择 Undertow 生成内存马

## GlassFish

> https://glassfish.org/

GlassFish 使用的是 Catalina 提供的 Servlets 实现，但是使用了 OSGI 类加载模式，因此类限制较为严重，在 MemShellParty 中，服务类型选择
GlassFish 进行内存马的生成。

## Payara

> https://www.payara.fish/downloads/

基于 GlassFish 开发，服务类型选择 GlassFish 进行内存马的生成。

## Resin

> https://caucho.com/products/resin/download

Resin 使用的包名为 `com.caucho.`，服务类型选择 Resin 进行内存马的生成。

泛微 OA 使用的就是 Resin 提供的服务。

## WebLogic

> https://www.oracle.com/middleware/technologies/weblogic-server-installers-downloads.html

WebLogic 使用的包名为 `weblogic.`，服务类型选择 WebLogic 进行内存马的生成。

## WebSphere

> https://www.ibm.com/products/websphere-application-server

WebSphere 是 IBM 研发的商用 Servlets 容器，开源版本为 Websphere liberty，
包名为 `com.ibm.`，服务类型选择 WebSphere 进行内存马的生成。

## BES

> https://www.bessystem.com/

BES 宝兰德，其基于 Tomcat 进行二开，在 BES 9.5.1 版本中没有进行包名修改，而在 BES 9.5.2
版本之后包名修改为了 `com.bes.enterprise.`。因此 BES 9.5.1 版本，服务类型选择 Tomcat 进行内存马的生成，BES 9.5.2+ 服务类型选择
BES 进行内存马的生成。

## TongWeb

> https://www.tongtech.com/sy.html

TongWeb 东方通，其基于 Tomcat 进行二开，并且在最初的 6 版本就进行了包名修改，每个版本都进行了修改。

- TongWeb6: `com.tongweb.web.thor.`
- TongWeb7: `com.tongweb.catalina.`
- TongWeb8: `com.tongweb.server.`

这三个版本在 MemShellParty 中均有适配，服务类型选择 TongWeb 进行内存马的生成。

## Apusic

> https://www.apusic.com/

金蝶中间件，Apusic9 疑似魔改自 GlassFish，不过改得面目全非了，自 Apusic10 开始使用原版 GlassFish 进行二开。因此 Apusic9
版本服务类型选择
Apusic 进行内存马生成，Apusic10 版本选择 GlassFish 进行内存马生成。

## Primeton

> https://www.primeton.com/products/pas/

普元中间件，Primeton6.5 版本基于 GlassFish
二开，高版本疑似做了包名修改，但没有环境，因此暂未适配（[#60](https://github.com/ReaJason/MemShellParty/issues/60)）因此当前仅支持
Primeton6.5 版本，服务类型选择 GlassFish 进行内存马生成。

## InforSuite

中创中间件，InforSuite 基于 GlassFish 进行二开，不过因为 InforSuite10 版本针对 filterConfigs 字段做了手脚改成了
iasFilterConfigs 因此 Filter 注入单独进行了适配。服务类型选择 InforSuite 进行内存马注入。

## SpringWebMVC

Spring 框架，默认的 MVC 架构，官方 Servlets 容器实现可选 Tomcat、Jetty 与 Undertow，也可打包成 war 包部署于任意 Servlets
容器上。内存马注入场景下不推荐框架内存马，而是具体的 Servlets 容器内存马，因为可绕过框架的限制（鉴权或其他）。服务类型选择
SpringWebMVC 进行内存马生成。

## SpringWebFlux

Spring Boot 项目中基于 reactor 异步 IO 模型的服务组件，底层使用的 Netty，一般常见于各种 SpringCloud 项目，例如网关。服务类型选择
SpringWebFlux 进行内存马生成。

