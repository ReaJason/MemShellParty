package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.service.SupportMatrixService;
import com.reajason.javaweb.boot.vo.CommandConfigVO;
import com.reajason.javaweb.boot.vo.PackerVO;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@RestController
@RequestMapping("/api/config")
@CrossOrigin("*")
public class ConfigController {

    private final SupportMatrixService supportMatrixService;

    public ConfigController(SupportMatrixService supportMatrixService) {
        this.supportMatrixService = supportMatrixService;
    }

    /**
     * @deprecated use {@link #config()} for memshell configuration and
     * {@link #getProbeResponseBodyServers()} for probe ResponseBody servers.
     */
    @RequestMapping("/servers")
    @Deprecated(since = "2.9.0", forRemoval = false)
    public Map<String, List<String>> getServers() {
        return supportMatrixService.servers();
    }

    /**
     * @deprecated use {@link #getPackerTree()} for parent/child packer metadata.
     */
    @RequestMapping("/packers")
    @Deprecated(since = "2.9.0", forRemoval = false)
    public List<String> getPackers() {
        return supportMatrixService.packers();
    }

    /**
     * 返回父/子 packer 层级结构，供前端在「父模式 / 子模式」之间选择。
     * 单独新增端点而非修改 {@link #getPackers()}，以避免破坏旧版本前端对返回值的依赖。
     */
    @RequestMapping("/packers/tree")
    public List<PackerVO> getPackerTree() {
        return supportMatrixService.packerTree();
    }

    @RequestMapping("/probe/response-body/servers")
    public List<String> getProbeResponseBodyServers() {
        return supportMatrixService.probeResponseBodyServers();
    }

    @RequestMapping
    public Map<String, Map<String, Set<String>>> config() {
        return supportMatrixService.config();
    }

    @GetMapping("/command/configs")
    public CommandConfigVO getCommandConfigs() {
        return supportMatrixService.commandConfigs();
    }
}
