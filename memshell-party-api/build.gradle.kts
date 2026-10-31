plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty SPI contracts and core types"

dependencies {
    api(project(":memshell-party-common"))
    implementation(libs.jackson.annotations)
    compileOnly(libs.javax.servlet.api)
}
