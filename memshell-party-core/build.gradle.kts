plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty generation engine"

dependencies {
    api(project(":memshell-party-api"))
    api(libs.jackson.annotations)
    implementation(libs.classobf) {
        // NOTE: class-obf is GPL-3.0 while this repository is MIT. Publishing this module to
        // Maven Central distributes a combined work; resolve licensing (isolate/replace/relicense)
        // before the next release.
        exclude(group = "org.yaml", module = "snakeyaml")
        exclude(group = "com.beust", module = "jcommander")
    }
    testImplementation(libs.junit.jupiter)
    // 自定义内存马归一化测试：生成期只提供 javax API，用来证明 jakarta 输入不依赖 jakarta jar
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.hamcrest)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    // class-obf 的相对路径临时文件已由 ClassObfuscation 重定向到每次调用的独立临时目录，
    // 不依赖 CWD，也无需按 test worker 隔离工作目录。
}
