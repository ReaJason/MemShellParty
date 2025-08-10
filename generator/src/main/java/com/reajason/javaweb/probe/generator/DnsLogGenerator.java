package com.reajason.javaweb.probe.generator;

import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.payload.JdkProbe;
import com.reajason.javaweb.probe.payload.ServerProbe;
import com.reajason.javaweb.probe.payload.dns.DnsLogJdk;
import com.reajason.javaweb.probe.payload.dns.DnsLogServer;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/6/29
 */
public class DnsLogGenerator extends ByteBuddyShellGenerator<DnsLogConfig> {

    public DnsLogGenerator(ProbeConfig probeConfig, DnsLogConfig probeContentConfig) {
        super(probeConfig, probeContentConfig);
    }

    @Override
    protected DynamicType.Builder<?> build(ByteBuddy buddy) {
        ProbeContent detectContent = probeConfig.getProbeContent();
        switch (detectContent) {
            case Server:
                return buddy.redefine(DnsLogServer.class)
                        .name(CommonUtil.generateShellClassName())
                        .visit(TargetJreVersionVisitorWrapper.DEFAULT)
                        .field(named("host")).value(probeContentConfig.getHost())
                        .visit(Advice.to(ServerProbe.class).on(named("getServer")));
            case JDK:
                return buddy.redefine(DnsLogJdk.class)
                        .name(CommonUtil.generateShellClassName())
                        .visit(TargetJreVersionVisitorWrapper.DEFAULT)
                        .field(named("host")).value(probeContentConfig.getHost())
                        .visit(Advice.to(JdkProbe.class).on(named("getJdk")));
            default:
                throw new UnsupportedOperationException(detectContent + " not supported");
        }
    }
}
