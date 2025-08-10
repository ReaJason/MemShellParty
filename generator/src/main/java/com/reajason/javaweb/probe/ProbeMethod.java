package com.reajason.javaweb.probe;

import com.reajason.javaweb.memshell.generator.ShellGenerator;
import com.reajason.javaweb.probe.config.*;
import com.reajason.javaweb.probe.generator.DnsLogGenerator;
import com.reajason.javaweb.probe.generator.SleepGenerator;
import com.reajason.javaweb.probe.generator.response.ResponseBodyGenerator;

import java.lang.reflect.Constructor;

/**
 * @author ReaJason
 * @since 2025/6/30
 */
public enum ProbeMethod {
    DNSLog(DnsLogGenerator.class, DnsLogConfig.class),
    ResponseBody(ResponseBodyGenerator.class, ResponseBodyConfig.class),
    Sleep(SleepGenerator.class, SleepConfig.class);

    private final Class<? extends ShellGenerator> generatorClass;
    private final Class<? extends ProbeContentConfig> configClass;

    ProbeMethod(Class<? extends ShellGenerator> generatorClass, Class<? extends ProbeContentConfig> configClass) {
        this.generatorClass = generatorClass;
        this.configClass = configClass;
    }

    public byte[] generateBytes(ProbeConfig probeConfig, ProbeContentConfig probeContentConfig) {
        try {
            Constructor<? extends ShellGenerator> constructor =
                    generatorClass.getConstructor(ProbeConfig.class, configClass);
            ShellGenerator generator = constructor.newInstance(probeConfig, configClass.cast(probeContentConfig));
            return generator.getBytes();
        } catch (Exception e) {
            throw new RuntimeException("shell generate failed: " + e.getMessage(), e);
        }
    }
}
