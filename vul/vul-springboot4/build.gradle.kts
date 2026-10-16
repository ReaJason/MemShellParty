plugins {
    id("java")
    id("war")
    id("org.springframework.boot") version "4.0.8"
    id("io.spring.dependency-management") version "1.1.7"
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    runtimeOnly("com.h2database:h2")
    implementation("ognl:ognl:2.7.3")
    implementation("commons-jxpath:commons-jxpath:1.3")
    implementation("commons-beanutils:commons-beanutils:1.9.3")
}

// CommandExec.java 是测试中 base64 payload 类的源文件，仅作再生成参考；
// 排除在测试编译之外，避免 JUnit 扫描加载并初始化该类，导致 static 块中的 RCE 动作被提前触发
tasks.compileTestJava {
    exclude("CommandExec.java")
}

tasks.test {
    useJUnitPlatform()
    // vul 各模块测试并行执行时共享系统临时目录，用独立标记文件名避免互相删除
    systemProperty("memshell.vul.rce.marker", "memshell-vul-rce-proof-sb4.txt")
}
