plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty Godzilla shell tool"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-core"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    // GodzillaNettyHandler: io.netty.*（此前经 dubbo 传递解析，现显式声明）
    compileOnly(libs.netty.all)
    // GodzillaJettyHandler/Customizer: org.eclipse.jetty.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-jetty"))
    // GodzillaValve: org.apache.catalina.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-tomcat"))
    // GodzillaWebSocket: javax.websocket.*（WebLogic 通过 ServerContainer 注册端点）
    compileOnly(libs.javax.websocket.api)
    // GodzillaRawWebSocket: 仅依赖 Servlet 3.1+，不使用 javax.websocket
    // GodzillaWebFilter/HandlerMethod/HandlerFunction: org.springframework.web.server.*/reactor（spring-web 由 webmvc 传递）
    compileOnly(libs.spring.webflux)
    // GodzillaInterceptor/ControllerHandler: org.springframework.web.servlet.*
    compileOnly(libs.spring.webmvc)
    // Servlet/Filter/Listener 模板: javax.servlet.*
    compileOnly(libs.javax.servlet.api)
    // 排除 Tomcat 桩：测试已用真 tomcat-embed-core 提供 catalina 签名，桩与它同包名，
    // 留在类路径上只会遮蔽真身（boot 上表现为 NoSuchMethodError: Adapter.getDomain()）
    testImplementation(project(":memshell-party-server:memshell-party-server-tomcat")) {
        exclude(group = "io.github.reajason", module = "memshell-party-stub-tomcat")
    }
    testImplementation(libs.junit.jupiter)
    // tomcat-embed-core 自带 servlet 3.1 类，必须排在 javax.servlet-api:3.0.1 前面，
    // 否则启动报 NoSuchMethodError: ServletContext.getVirtualServerName()
    testImplementation(libs.tomcat.embed.core)
    testImplementation(libs.javax.servlet.api)
    // 测试要加载 GodzillaWebSocket（implements javax.websocket MessageHandler）
    testImplementation(libs.javax.websocket.api)
    // Jakarta 变体生成的类要能被加载（加载后才能断言字段）
    testImplementation(libs.jakarta.servlet.api)
    // 端到端测试：内嵌 Tomcat 跑内存马 + 仓库内的哥斯拉协议客户端（tools:godzilla）
    testImplementation(project(":tools:godzilla"))
    testImplementation(libs.okhttp3)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
