package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationInfo;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerSupport;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import org.springframework.stereotype.Service;

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
        String packerName = normalizePacker(request.getPacker());
        Packer packer = packerName.isEmpty() ? null : PackerRegistry.getInstance().get(packerName);
        // SpringGzipJDK17 系打包器要求类位于 org.springframework.expression 包下；
        // 调用方没给（配置默认值不在该包）或给了别的包时在服务端补齐，REST/MCP 共用同一份实现。
        if (packer != null && packer.requiresSpringExpressionPackage()
                && (injectorConfig == null
                || !PackerSupport.isSpringExpressionClassName(injectorConfig.getInjectorClassName()))) {
            if (injectorConfig == null) {
                injectorConfig = InjectorConfig.builder().build();
            }
            injectorConfig.setInjectorClassName(packer.generateSpringExpressionClassName());
        }
        MemShellResult generateResult = memShellGenerator.generate(shellConfig, injectorConfig, shellToolParams);
        String payload = PackerRegistry.getInstance().pack(packerName, generateResult);
        recordHeaderPayload(generateResult.getObfuscationInfo(), packer, payload);
        return new MemShellGenerateResponse(generateResult, payload);
    }

    public ProbeShellGenerateResponse generateProbeShell(ProbeShellGenerateRequest request) {
        ProbeConfig probeConfig = request.getProbeConfig();
        ProbeContentConfig probeContentConfig = request.parseProbeContentConfig();
        String packerName = normalizePacker(request.getPacker());
        Packer packer = packerName.isEmpty() ? null : PackerRegistry.getInstance().get(packerName);
        if (packer != null && packer.requiresSpringExpressionPackage()
                && !PackerSupport.isSpringExpressionClassName(probeConfig.getShellClassName())) {
            probeConfig.setShellClassName(packer.generateSpringExpressionClassName());
        }
        ProbeShellResult generateResult = ProbeShellGenerator.generate(probeConfig, probeContentConfig);
        String payload = PackerRegistry.getInstance().pack(packerName, generateResult);
        recordHeaderPayload(generateResult.getObfuscationInfo(), packer, payload);
        return new ProbeShellGenerateResponse(generateResult, payload);
    }

    private static String normalizePacker(String packer) {
        return packer == null ? "" : packer.trim();
    }

    private static void recordHeaderPayload(ObfuscationInfo info, Packer packer, String payload) {
        long size = payload == null ? 0 : payload.length();
        recordHeaderPayload(info, packer, size);
    }

    /**
     * 只有经 HTTP Header 传输的 packer 才记录打包后体积；4KB 限制针对最终载荷，
     * 而不是混淆前的 class 大小，避免对 JSP/Base64 等场景误报。
     */
    private static void recordHeaderPayload(ObfuscationInfo info, Packer packer, long size) {
        if (info != null && info.isEnabled() && packer != null && packer.headerTransported()) {
            info.recordPackedPayloadSize(size);
        }
    }

}
