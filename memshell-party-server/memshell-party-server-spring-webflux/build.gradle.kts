plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty SpringWebFlux server support"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-api"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    // 生成期只按字节解析模板父类链，spring-webflux 本身之外的 Spring 运行时依赖
    // （IoC/AOP/SpEL/JCL）不会在生成或运行时被用到，别让它们跟着 fat jar 发出去
    implementation(libs.spring.webflux) {
        exclude(group = "org.springframework", module = "spring-beans")
        exclude(group = "org.springframework", module = "spring-context")
        exclude(group = "org.springframework", module = "spring-aop")
        exclude(group = "org.springframework", module = "spring-expression")
        exclude(group = "org.springframework", module = "spring-jcl")
    }
    // 注入器模板引用了 RequestMappingHandlerMapping / RouterFunctionMapping，javac 解析它们的
    // 父链接口（InitializingBean、ApplicationObjectSupport…）时需要这些签名；生成引擎只按字节
    // 解析模板自身，不解析这些父链，所以编译期够用即可，不进运行时
    compileOnly(libs.spring.context)
    // reactor-netty 只提供模板父类签名；DNS/原生传输等可选实现不参与生成，断开后显著缩小 fat jar
    implementation(libs.reactor.netty.core) {
        exclude(group = "io.netty", module = "netty-resolver-dns")
        exclude(group = "io.netty", module = "netty-codec-dns")
        exclude(group = "io.netty", module = "netty-codec-socks")
        exclude(group = "io.netty", module = "netty-transport-native-epoll")
        exclude(group = "io.netty", module = "netty-resolver-dns-native-macos")
        exclude(group = "io.netty", module = "netty-resolver-dns-classes-macos")
    }
}
