plugins {
    id("war")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation("commons-fileupload:commons-fileupload:1.3.3")
    implementation("commons-beanutils:commons-beanutils:1.9.3")
    implementation("de.odysseus.juel:juel-impl:2.2.7")
    implementation("org.freemarker:freemarker:2.3.23")
    implementation("commons-io:commons-io:2.19.0")
    implementation("org.apache.velocity:velocity:1.7")
    implementation("ognl:ognl:2.7.3")
    implementation("org.mvel:mvel2:2.4.7.Final")
    implementation("org.beanshell:bsh:2.0b5")
    implementation("org.apache.commons:commons-jexl:2.1.1")
    implementation("org.apache.commons:commons-jexl3:3.2.1")
    implementation("commons-jxpath:commons-jxpath:1.3")
    implementation("com.googlecode.aviator:aviator:5.2.7")
    implementation("org.codehaus.groovy:groovy:3.0.6")
    implementation("org.mozilla:rhino:1.7.14")
    implementation("com.hubspot.jinjava:jinjava:2.4.5")
    implementation("org.springframework:spring-expression:4.3.0.RELEASE")
    providedCompile("de.odysseus.juel:juel-api:2.2.7")
    providedCompile("javax.servlet:javax.servlet-api:3.1.0")
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}
