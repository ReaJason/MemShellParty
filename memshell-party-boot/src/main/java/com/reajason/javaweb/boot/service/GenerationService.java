package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationInfo;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Map;

/**
 * Shared generation logic for the REST controllers and the MCP tools.
 *
 * @author ReaJason
 * @since 2026/9/30
 */
@Service
public class GenerationService {

    private final MemShellGenerator memShellGenerator;

    public GenerationService(MemShellGenerator memShellGenerator) {
        this.memShellGenerator = memShellGenerator;
    }

    public MemShellGenerateResponse generateMemShell(MemShellGenerateRequest request) {
        ShellConfig shellConfig = request.getShellConfig();
        Map<String, String> shellToolParams = request.getShellToolConfig();
        InjectorConfig injectorConfig = request.getInjectorConfig();
        // SpringGzipJDK17 系打包器要求类位于 org.springframework.expression 包下；
        // 调用方没给（配置默认值不在该包）或给了别的包时在服务端补齐，REST/MCP 共用同一份实现。
        if (request.getPacker().requiresSpringExpressionPackage()
                && (injectorConfig == null
                || !Packers.isSpringExpressionClassName(injectorConfig.getInjectorClassName()))) {
            if (injectorConfig == null) {
                injectorConfig = InjectorConfig.builder().build();
            }
            injectorConfig.setInjectorClassName(request.getPacker().generateSpringExpressionClassName());
        }
        MemShellResult generateResult = memShellGenerator.generate(shellConfig, injectorConfig, shellToolParams);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof AggregatePacker) {
            Map<String, String> packed = ((AggregatePacker) packer).packAll(ClassPackerConfig.from(generateResult));
            recordHeaderPayload(generateResult.getObfuscationInfo(), packer, packed);
            return new MemShellGenerateResponse(generateResult, packed);
        }
        if (packer instanceof JarPacker) {
            String packed = Base64.getEncoder().encodeToString(
                    ((JarPacker) packer).packBytes(JarPackerConfig.from(generateResult)));
            recordHeaderPayload(generateResult.getObfuscationInfo(), packer, packed.length());
            return new MemShellGenerateResponse(generateResult, packed);
        }
        String packed = packer.pack(ClassPackerConfig.from(generateResult));
        recordHeaderPayload(generateResult.getObfuscationInfo(), packer,
                packed == null ? 0 : packed.length());
        return new MemShellGenerateResponse(generateResult, packed);
    }

    public ProbeShellGenerateResponse generateProbeShell(ProbeShellGenerateRequest request) {
        ProbeConfig probeConfig = request.getProbeConfig();
        ProbeContentConfig probeContentConfig = request.parseProbeContentConfig();
        if (request.getPacker().requiresSpringExpressionPackage()
                && !Packers.isSpringExpressionClassName(probeConfig.getShellClassName())) {
            probeConfig.setShellClassName(request.getPacker().generateSpringExpressionClassName());
        }
        ProbeShellResult generateResult = ProbeShellGenerator.generate(probeConfig, probeContentConfig);
        ClassPackerConfig packerConfig = ClassPackerConfig.of(generateResult.getShellClassName(), generateResult.getShellBytes(),
                generateResult.getShellBytesBase64Str(), generateResult.getProbeConfig() != null && generateResult.getProbeConfig().needByPassJavaModule());
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof AggregatePacker) {
            Map<String, String> packed = ((AggregatePacker) packer).packAll(packerConfig);
            recordHeaderPayload(generateResult.getObfuscationInfo(), packer, packed);
            return new ProbeShellGenerateResponse(generateResult, packed);
        }
        String packed = packer.pack(packerConfig);
        recordHeaderPayload(generateResult.getObfuscationInfo(), packer,
                packed == null ? 0 : packed.length());
        return new ProbeShellGenerateResponse(generateResult, packed);
    }

    /**
     * 只有经 HTTP Header 传输的 packer 才记录打包后体积；4KB 限制针对最终载荷，
     * 而不是混淆前的 class 大小，避免对 JSP/Base64 等场景误报。
     */
    private static void recordHeaderPayload(ObfuscationInfo info, Packer packer, Map<String, String> packed) {
        if (packed == null || packed.isEmpty()) {
            return;
        }
        long max = 0;
        for (String value : packed.values()) {
            if (value != null) {
                max = Math.max(max, value.length());
            }
        }
        recordHeaderPayload(info, packer, max);
    }

    private static void recordHeaderPayload(ObfuscationInfo info, Packer packer, long size) {
        if (info != null && info.isEnabled() && packer != null && packer.headerTransported()) {
            info.recordPackedPayloadSize(size);
        }
    }

}
