plugins {
    id("java8-library-conventions")
}

description = "Dubbo compile-time stubs for MemShellParty shell templates (com.alibaba 2.6 / org.apache 2.7, compileOnly only, never ship at runtime)"

dependencies {
    // ClassGenerator.getClassPool 的返回类型；桩只用于编译，由目标环境的 Dubbo 自带真身
    compileOnly(libs.javassist)
}
