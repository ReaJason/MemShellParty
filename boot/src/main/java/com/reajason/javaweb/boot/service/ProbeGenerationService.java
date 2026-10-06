package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import org.springframework.stereotype.Service;

/**
 * 探测马生成的唯一入口，供 REST 与 MCP 两种接口共用。
 *
 * @author ReaJason
 */
@Service
public class ProbeGenerationService {

    /**
     * 生成探测马并按指定打包器打包。
     * <p>
     * 探测马不产出 jar，故只有聚合与单文件两种分支。
     */
    public GenerationOutcome<ProbeShellResult> generate(ProbeConfig probeConfig,
                                                        ProbeContentConfig probeContentConfig,
                                                        Packers packer) {
        ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, probeContentConfig);
        Packer instance = packer.getInstance();
        if (instance instanceof AggregatePacker aggregatePacker) {
            return GenerationOutcome.ofAggregate(result, aggregatePacker.packAll(result.toClassPackerConfig()));
        }
        return GenerationOutcome.ofSingle(result, instance.pack(result.toClassPackerConfig()));
    }
}
