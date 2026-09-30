package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.util.Base64;

/**
 * Shared generation logic for the REST controllers and the MCP tools.
 *
 * @author ReaJason
 * @since 2026/9/30
 */
@Service
public class GenerationService {

    public MemShellGenerateResponse generateMemShell(MemShellGenerateRequest request) {
        normalize(request);
        ShellConfig shellConfig = request.getShellConfig();
        ShellToolConfig shellToolConfig = request.parseShellToolConfig();
        InjectorConfig injectorConfig = request.getInjectorConfig();
        MemShellResult generateResult = MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof AggregatePacker) {
            return new MemShellGenerateResponse(generateResult, ((AggregatePacker) packer).packAll(generateResult.toClassPackerConfig()));
        }
        if (packer instanceof JarPacker) {
            return new MemShellGenerateResponse(generateResult, Base64.getEncoder().encodeToString(((JarPacker) packer).packBytes(generateResult.toJarPackerConfig())));
        }
        return new MemShellGenerateResponse(generateResult, packer.pack(generateResult.toClassPackerConfig()));
    }

    public ProbeShellGenerateResponse generateProbeShell(ProbeShellGenerateRequest request) {
        normalize(request);
        ProbeConfig probeConfig = request.getProbeConfig();
        ProbeContentConfig probeContentConfig = request.parseProbeContentConfig();
        ProbeShellResult generateResult = ProbeShellGenerator.generate(probeConfig, probeContentConfig);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof AggregatePacker) {
            return new ProbeShellGenerateResponse(generateResult, ((AggregatePacker) packer).packAll(generateResult.toClassPackerConfig()));
        }
        return new ProbeShellGenerateResponse(generateResult, packer.pack(generateResult.toClassPackerConfig()));
    }

    /**
     * Jackson 反序列化走无参构造，拿不到 {@code @Builder.Default} 标注的默认值，
     * 这里按字段文档约定补齐缺省值，保证 REST 和 MCP 客户端都可以只传必要字段。
     */
    private static void normalize(MemShellGenerateRequest request) {
        ShellConfig shellConfig = request.getShellConfig();
        if (StringUtils.isBlank(shellConfig.getServerVersion())) {
            shellConfig.setServerVersion("unknown");
        }
        if (shellConfig.getTargetJreVersion() == 0) {
            shellConfig.setTargetJreVersion(Opcodes.V1_6);
        }
        if (request.getShellToolConfig() == null) {
            request.setShellToolConfig(new MemShellGenerateRequest.ShellToolConfigDTO());
        }
        if (request.getInjectorConfig() == null) {
            request.setInjectorConfig(InjectorConfig.builder().build());
        }
        InjectorConfig injectorConfig = request.getInjectorConfig();
        if (StringUtils.isBlank(injectorConfig.getInjectorClassName())) {
            injectorConfig.setInjectorClassName(CommonUtil.generateInjectorClassName());
        }
        if (StringUtils.isBlank(injectorConfig.getUrlPattern())) {
            injectorConfig.setUrlPattern("/*");
        }
    }

    private static void normalize(ProbeShellGenerateRequest request) {
        ProbeConfig probeConfig = request.getProbeConfig();
        if (StringUtils.isBlank(probeConfig.getShellClassName())) {
            probeConfig.setShellClassName(CommonUtil.generateInjectorClassName());
        }
        if (probeConfig.getTargetJreVersion() == 0) {
            probeConfig.setTargetJreVersion(Opcodes.V1_6);
        }
    }
}
