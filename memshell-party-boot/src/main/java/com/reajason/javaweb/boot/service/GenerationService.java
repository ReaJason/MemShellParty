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
import com.reajason.javaweb.packer.PackerConstraints;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Objects;

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
        PackerConstraints constraints = PackerConstraints.forPacker(request.getPacker());
        constraints.constrainObfuscation(shellConfig.getObfuscation());
        String requestedClassName = injectorConfig == null ? null : injectorConfig.getInjectorClassName();
        String requiredClassName = constraints.enforceClassName(requestedClassName);
        if (!Objects.equals(requestedClassName, requiredClassName)) {
            if (injectorConfig == null) {
                injectorConfig = InjectorConfig.builder().build();
            }
            injectorConfig.setInjectorClassName(requiredClassName);
        }
        MemShellResult generateResult = memShellGenerator.generate(shellConfig, injectorConfig, shellToolParams);
        String payload = PackerRegistry.getInstance().pack(constraints.getPackerName(), generateResult);
        return new MemShellGenerateResponse(generateResult, payload);
    }

    public ProbeShellGenerateResponse generateProbeShell(ProbeShellGenerateRequest request) {
        ProbeConfig probeConfig = request.getProbeConfig();
        ProbeContentConfig probeContentConfig = request.parseProbeContentConfig();
        PackerConstraints constraints = PackerConstraints.forPacker(request.getPacker());
        constraints.constrainObfuscation(probeConfig.getObfuscation());
        probeConfig.setShellClassName(constraints.enforceClassName(probeConfig.getShellClassName()));
        ProbeShellResult generateResult = ProbeShellGenerator.generate(probeConfig, probeContentConfig);
        String payload = PackerRegistry.getInstance().pack(constraints.getPackerName(), generateResult);
        return new ProbeShellGenerateResponse(generateResult, payload);
    }

}
