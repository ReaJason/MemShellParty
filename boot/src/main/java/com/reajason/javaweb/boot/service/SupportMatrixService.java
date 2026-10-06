package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.boot.vo.CommandConfigVO;
import com.reajason.javaweb.boot.vo.PackerVO;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.generator.response.ResponseBodyGenerator;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 能力矩阵查询：服务端 / 打包器 / 命令配置的受支持组合。
 * <p>
 * 抽自 {@code ConfigController}，使 REST 与 MCP 共享同一份能力定义，
 * 避免两处枚举逻辑漂移。
 *
 * @author ReaJason
 */
@Service
public class SupportMatrixService {

    /**
     * 服务端到「内存马功能再到内存马类型」的两级映射，空组合被过滤。
     */
    public Map<String, Map<String, Set<String>>> config() {
        Map<String, Map<String, Set<String>>> coreMap = new LinkedHashMap<>(16);
        for (String supportedServer : ServerFactory.getSupportedServers()) {
            AbstractServer server = ServerFactory.getServer(supportedServer);
            Map<String, Set<String>> map = new LinkedHashMap<>(16);
            for (String shellTool : server.getSupportedShellTools()) {
                Set<String> supportedShellTypes = server.getSupportedShellTypes(shellTool);
                if (supportedShellTypes.isEmpty()) {
                    continue;
                }
                map.put(shellTool, supportedShellTypes);
            }
            coreMap.put(supportedServer, map);
        }
        return coreMap;
    }

    /**
     * 顶层打包器及其子打包器，供「父模式 / 子模式」选择。
     */
    public List<PackerVO> packerTree() {
        return Arrays.stream(Packers.values())
                .filter(packers -> packers.getParentPacker() == null)
                .map(packers -> new PackerVO(
                        packers.name(),
                        Packers.getPackersWithParent(packers.getInstance().getClass())
                                .stream().map(Packers::name).toList()))
                .toList();
    }

    public CommandConfigVO commandConfigs() {
        CommandConfigVO commandConfigVO = new CommandConfigVO();
        commandConfigVO.setEncryptors(Arrays.stream(CommandConfig.Encryptor.values()).toList());
        commandConfigVO.setImplementationClasses(Arrays.stream(CommandConfig.ImplementationClass.values()).toList());
        return commandConfigVO;
    }

    public List<String> probeResponseBodyServers() {
        return ResponseBodyGenerator.getSupportedServers();
    }

    /**
     * 各探测方式支持的 probeContent 取值。
     * <p>
     * 镜像自各生成器的 switch 分支（{@code DnsLogGenerator} / {@code SleepGenerator} /
     * {@code ResponseBodyGenerator}）。生成器侧未提供内省接口，故在此显式声明——
     * 这样调用方无需靠试错来发现合法组合。新增 probeContent 时需同步此表。
     */
    public Map<String, List<String>> probeContentsByMethod() {
        Map<String, List<String>> byMethod = new LinkedHashMap<>(4);
        byMethod.put(ProbeMethod.DNSLog.name(),
                List.of(ProbeContent.Server.name(), ProbeContent.JDK.name()));
        byMethod.put(ProbeMethod.Sleep.name(),
                List.of(ProbeContent.Server.name()));
        byMethod.put(ProbeMethod.ResponseBody.name(),
                List.of(ProbeContent.Command.name(), ProbeContent.Bytecode.name(),
                        ProbeContent.Filter.name(), ProbeContent.ScriptEngine.name()));
        return byMethod;
    }

    /**
     * @deprecated 使用 {@link #config()} 与 {@link #probeResponseBodyServers()} 替代。
     */
    @Deprecated(since = "2.9.0", forRemoval = false)
    public Map<String, List<String>> servers() {
        Map<String, List<String>> servers = new LinkedHashMap<>();
        for (String supportedServer : ServerFactory.getSupportedServers()) {
            Set<String> supportedShellTypes = ServerFactory.getServer(supportedServer)
                    .getShellInjectorMapping().getSupportedShellTypes();
            servers.put(supportedServer, supportedShellTypes.stream().toList());
        }
        return servers;
    }

    /**
     * @deprecated 使用 {@link #packerTree()} 替代。
     */
    @Deprecated(since = "2.9.0", forRemoval = false)
    public List<String> packers() {
        return Arrays.stream(Packers.values())
                .filter(packers -> packers.getParentPacker() == null)
                .map(Packers::name).toList();
    }
}
