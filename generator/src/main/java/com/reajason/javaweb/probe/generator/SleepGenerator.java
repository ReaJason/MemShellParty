package com.reajason.javaweb.probe.generator;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.SleepConfig;
import com.reajason.javaweb.probe.payload.ServerProbe;
import com.reajason.javaweb.probe.payload.sleep.SleepServer;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.lang3.StringUtils;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/6/29
 */
public class SleepGenerator extends ByteBuddyShellGenerator<SleepConfig> {


    public SleepGenerator(ProbeConfig probeConfig, SleepConfig probeContentConfig) {
        super(probeConfig, probeContentConfig);
    }

    @Override
    protected DynamicType.Builder<?> build(ByteBuddy buddy) {
        ProbeContent detectContent = probeConfig.getProbeContent();
        if (ProbeContent.Server.equals(detectContent)) {
            if (probeContentConfig.getSeconds() <= 0) {
                throw new GenerationException("sleepProbe seconds must be greater than 0");
            }
            if (StringUtils.isEmpty(probeContentConfig.getServer())) {
                throw new GenerationException("sleepProbe server must be specified");
            }
            return buddy.redefine(SleepServer.class)
                    .name(probeConfig.getShellClassName())
                    .visit(TargetJreVersionVisitorWrapper.DEFAULT)
                    .field(named("server")).value(probeContentConfig.getServer())
                    .field(named("seconds")).value(probeContentConfig.getSeconds())
                    .visit(Advice.to(ServerProbe.class).on(named("getServer")));
        }
        throw new GenerationException("sleepProbe not supported for " + detectContent);
    }
}