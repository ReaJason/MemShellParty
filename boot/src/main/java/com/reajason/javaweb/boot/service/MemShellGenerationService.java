package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import org.springframework.stereotype.Service;

import java.util.Base64;

/**
 * 内存马生成的唯一入口，供 REST 与 MCP 两种接口共用。
 *
 * @author ReaJason
 */
@Service
public class MemShellGenerationService {

    /**
     * 生成内存马并按指定打包器打包。
     * <p>
     * 打包分支：{@link AggregatePacker} 产出全部子打包器结果；{@link JarPacker} 产出 jar 的 Base64；
     * 其余产出单个字符串载荷。
     */
    public GenerationOutcome<MemShellResult> generate(ShellConfig shellConfig,
                                                      InjectorConfig injectorConfig,
                                                      ShellToolConfig shellToolConfig,
                                                      Packers packer) {
        MemShellResult result = MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);
        Packer instance = packer.getInstance();
        if (instance instanceof AggregatePacker aggregatePacker) {
            return GenerationOutcome.ofAggregate(result, aggregatePacker.packAll(result.toClassPackerConfig()));
        }
        if (instance instanceof JarPacker jarPacker) {
            return GenerationOutcome.ofSingle(result,
                    Base64.getEncoder().encodeToString(jarPacker.packBytes(result.toJarPackerConfig())));
        }
        return GenerationOutcome.ofSingle(result, instance.pack(result.toClassPackerConfig()));
    }
}
