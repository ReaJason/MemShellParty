package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import com.reajason.javaweb.memshell.obfuscation.OptionRegistry;
import com.reajason.javaweb.packer.PackerCategory;
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
     * 返回「分组 - 变体」两级 packer 目录，供前端选择具体变体。分组名可以没有同名 packer。
     */
    @RequestMapping("/packers/tree")
    public List<PackerCategory> getPackerTree() {
        return PackerRegistry.getInstance().getTree();
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

    /**
     * 混淆参数目录：参数名、类型、默认值、取值范围与说明，供前端「参数参考」弹窗展示可填项。
     * <p>
     * 数据源是 {@link OptionRegistry} 注册表（与 MCP memshell_capabilities 的 obfuscationOptions 一致）。
     * class-obf 上游还有本表未覆盖的配置（badAnno 文件类、junk 等），那些因安全/基线原因刻意不暴露，
     * 不能直接把上游文档当参数说明。
     */
    @GetMapping("/obfuscation/options")
    public List<Map<String, Object>> getObfuscationOptions() {
        return OptionRegistry.describeAll();
    }
}
