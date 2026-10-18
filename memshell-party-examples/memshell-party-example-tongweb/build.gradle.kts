plugins {
    id("java")
}

group = "io.github.reajason"
description = "Example that pins how TongWebExploit consumes MemShellParty"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    // Generation engine (pulls in memshell-party-api + memshell-party-common)
    implementation(project(":memshell-party-core"))

    // Only the server the tool targets — TongWeb (pulls in server-tomcat, its base).
    // 排除随之传递的 Tomcat 桩：本模块运行期/测试都有真 tomcat-embed-core 提供签名，
    // 桩与它同包名并存会遮蔽真身（boot 上表现为 NoSuchMethodError: Adapter.getDomain()）
    implementation(project(":memshell-party-server:memshell-party-server-tongweb")) {
        exclude(group = "io.github.reajason", module = "memshell-party-stub-tomcat")
    }

    // Only the shell tools the tool offers — each registers itself via SPI
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-godzilla"))
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-behinder"))
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-command"))
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-suo5"))
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-antsword"))
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-neoregeorg"))

    // Generation-time only: the shell template's supertype chain must be resolvable as
    // bytes (they are never loaded into the JVM). Add only what your shell types need:
    //   Filter/Listener/Servlet (and their Jakarta* variants) -> javax.servlet-api
    //   Valve/ProxyValve                                        -> tomcat-embed-core
    //   Agent*                                                  -> nothing
    // These are deliberately NOT transitive deps of the shell-tool modules, so consumers
    // never shade APIs of servers they do not target (spring, dubbo, reactor, ...).
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.tomcat.embed.core)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

// Prints what a consumer actually shades when embedding MemShellParty:
// ./gradlew :memshell-party-examples:memshell-party-example-tongweb:measureRuntimeFootprint
tasks.register("measureRuntimeFootprint") {
    description = "Prints the total runtime footprint a consumer of these modules ships"
    group = "verification"
    doLast {
        fun File.sizeBytes(): Long =
            if (isFile) length() else walkBottomUp().filter { it.isFile }.sumOf { it.length() }

        var total = 0L
        configurations.runtimeClasspath.get().files.sortedBy { it.name }.forEach {
            val size = it.sizeBytes()
            total += size
            println("%10.1f KB  %s".format(size / 1024.0, it.name))
        }
        println("----------")
        println("TOTAL: %.2f MB".format(total / 1024.0 / 1024.0))
    }
}
