package com.reajason.javaweb.probe;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import com.reajason.javaweb.probe.config.SleepConfig;
import com.reajason.javaweb.probe.generator.DnsLogGenerator;
import com.reajason.javaweb.probe.generator.SleepGenerator;
import com.reajason.javaweb.probe.generator.response.ResponseGenerator;
import lombok.SneakyThrows;

import java.lang.reflect.Constructor;

final class ProbeMethodDispatcher {

    private ProbeMethodDispatcher() {
    }

    @SneakyThrows
    static byte[] generateBytes(ProbeConfig probeConfig, ProbeContentConfig probeContentConfig) {
        Class<? extends ShellGenerator> generatorClass;
        Class<? extends ProbeContentConfig> configClass;
        switch (probeConfig.getProbeMethod()) {
            case DNSLog:
                generatorClass = DnsLogGenerator.class;
                configClass = DnsLogConfig.class;
                break;
            case ResponseBody:
            case ResponseHeader:
                generatorClass = ResponseGenerator.class;
                configClass = ResponseConfig.class;
                break;
            case Sleep:
                generatorClass = SleepGenerator.class;
                configClass = SleepConfig.class;
                break;
            default:
                throw new IllegalArgumentException("Unknown probe method: " + probeConfig.getProbeMethod());
        }
        Constructor<? extends ShellGenerator> constructor =
                generatorClass.getConstructor(ProbeConfig.class, configClass);
        ShellGenerator generator = constructor.newInstance(probeConfig, configClass.cast(probeContentConfig));
        return generator.getBytes();
    }
}
