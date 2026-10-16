package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packer;
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
        MemShellResult generateResult = memShellGenerator.generate(shellConfig, injectorConfig, shellToolParams);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof AggregatePacker) {
            return new MemShellGenerateResponse(generateResult, ((AggregatePacker) packer).packAll(ClassPackerConfig.from(generateResult)));
        }
        if (packer instanceof JarPacker) {
            return new MemShellGenerateResponse(generateResult, Base64.getEncoder().encodeToString(((JarPacker) packer).packBytes(JarPackerConfig.from(generateResult))));
        }
        return new MemShellGenerateResponse(generateResult, packer.pack(ClassPackerConfig.from(generateResult)));
    }

    public ProbeShellGenerateResponse generateProbeShell(ProbeShellGenerateRequest request) {
        ProbeConfig probeConfig = request.getProbeConfig();
        ProbeContentConfig probeContentConfig = request.parseProbeContentConfig();
        ProbeShellResult generateResult = ProbeShellGenerator.generate(probeConfig, probeContentConfig);
        ClassPackerConfig packerConfig = ClassPackerConfig.of(generateResult.getShellClassName(), generateResult.getShellBytes(),
                generateResult.getShellBytesBase64Str(), generateResult.getProbeConfig() != null && generateResult.getProbeConfig().needByPassJavaModule());
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof AggregatePacker) {
            return new ProbeShellGenerateResponse(generateResult, ((AggregatePacker) packer).packAll(packerConfig));
        }
        return new ProbeShellGenerateResponse(generateResult, packer.pack(packerConfig));
    }

}
