plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "MemShellParty XxlJob server support"

dependencies {
    api(project(":memshell-party-api"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    // 注入器只继承 ChannelInitializer 并引用 ChannelHandler / SocketChannel，父链与泛型都在
    // netty-transport 里；无需 reactor-netty-core（会带进 reactor-core、handler/codec、
    // DNS/epoll 原生传输等一整条生成期用不到的链）
    implementation(libs.netty.transport)
}
