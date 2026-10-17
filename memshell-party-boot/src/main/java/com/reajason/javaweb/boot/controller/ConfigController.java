package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import com.reajason.javaweb.packer.PackerCategory;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.generator.response.ResponseGenerator;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@RestController
@RequestMapping("/api/config")
@CrossOrigin("*")
public class ConfigController {

    private final MemShellGenerator memShellGenerator;

    public ConfigController(MemShellGenerator memShellGenerator) {
        this.memShellGenerator = memShellGenerator;
    }

    /**
     * 返回父/子 packer 层级结构，供前端在「父模式 / 子模式」之间选择。
     */
    @RequestMapping("/packers/tree")
    public List<PackerCategory> getPackerTree() {
        return Packers.getPackerTree();
    }

    @RequestMapping("/probe/response/servers")
    public List<String> getProbeResponseServers() {
        return ResponseGenerator.getSupportedServers();
    }

    @RequestMapping
    public Map<String, Map<String, List<String>>> config() {
        return memShellGenerator.getShellTypeCatalog().asMap();
    }

    /**
     * 每个 shell tool 的可配置参数：参数名、值类型（string / enum）、枚举可选值与基础/高级分组。
     * <p>
     * 取自各 config 类上的 {@code @ConfigField} 注解，字段声明顺序即表单顺序，
     * 所以新增工具只要给字段加注解即可，web 与桌面端无需改代码。
     */
    @GetMapping("/shelltool/configs")
    public List<ToolConfigFactory.ToolConfigDescriptor> getShellToolConfigs() {
        return ToolConfigFactory.describeAll();
    }
}
