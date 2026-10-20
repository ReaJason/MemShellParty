package com.reajason.javaweb.packer;

import com.reajason.javaweb.memshell.PackerRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 下游 exclude 掉 JNA 后（类路径上没有 jna / jna-platform）：
 * 依赖 JNA 的 AgentJar 附加器不再注册，其余 packer 与整个注册表照常工作。
 *
 * <p>由 {@code noJnaTest} 任务在裁剪过的类路径上执行；普通 test 任务按 tag 排除。
 *
 * @author ReaJason
 */
@Tag("no-jna")
class PackerRegistryWithoutJnaTest {

    @BeforeEach
    @AfterEach
    void resetRegistry() {
        PackerRegistry.getInstance().reset();
    }

    @Test
    void jnaDependentPackersAreSkipped() {
        List<String> names = PackerRegistry.getInstance().getNames();

        assertFalse(names.contains(Packers.AgentJarWithJDKAttacher));
        assertFalse(names.contains(Packers.AgentJarWithJREAttacher));
        // 不依赖 JNA 的 packer 全部保留（77 - 2 个 JNA 项 + 测试 fixture）
        assertTrue(names.contains("ThirdPartyFixture"), "其余 SPI 条目不应受影响");
        assertTrue(names.contains(Packers.AgentJar));
        assertTrue(names.contains(Packers.DefaultBase64));
        assertTrue(names.contains(Packers.JavaCommonsBeanutils19));
        assertTrue(names.size() >= 76, "只应少掉两个依赖 JNA 的注册名，实际：" + names.size());

        assertTrue(PackerRegistry.getInstance().getLoadErrors().stream()
                .noneMatch(message -> message.contains("AgentJarWith")),
                "可选依赖缺失属于预期过滤，不应作为加载错误：" + PackerRegistry.getInstance().getLoadErrors());
    }
}
