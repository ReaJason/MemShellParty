package com.reajason.javaweb.desktop.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 完整发行版冒烟测试：本模块是「SDK + server-all + shelltool-all」的装配体，
 * 唯一保证开箱即用的地方 —— 全部内置 server 与 shelltool 都在类路径上被 SPI 发现，
 * 且能真的生成出内存马。
 *
 * <p>SDK 自己的测试把 server-all 只当测试夹具用，所以这里再钉一遍装配结果：少引一个
 * provider 模块，用户拿到的完整 jar 就会少一个 server/工具，这条用例会红。
 */
class FullGuiCatalogTest {

    private static final List<String> ALL_SERVERS = Arrays.asList(
            Server.Tomcat, Server.Jetty, Server.Jetty5, Server.Undertow, Server.JBoss,
            Server.Resin, Server.Resin2, Server.WebLogic, Server.WebSphere, Server.GlassFish,
            Server.TongWeb, Server.BES, Server.InforSuite, Server.Apusic,
            Server.SpringWebMvc, Server.SpringWebFlux, Server.XXLJOB, Server.Struts2, Server.Dubbo);

    private static final List<String> ALL_SHELL_TOOLS = Arrays.asList(
            ShellTool.Godzilla, ShellTool.GodzillaSession, ShellTool.Behinder, ShellTool.Command,
            ShellTool.Suo5, ShellTool.AntSword, ShellTool.NeoreGeorg, ShellTool.Proxy, ShellTool.Custom);

    @Test
    void everyBuiltInServerAndShellToolIsOnTheClasspath() {
        MemShellFormController controller = controller();

        assertTrue(controller.getServers().containsAll(ALL_SERVERS),
                "缺少内置 server：" + difference(ALL_SERVERS, controller.getServers()));

        // 工具列表是「server 支持的注入器映射 × 工具声明」求交集，逐个 server 汇总后再断言，
        // 避免把单个 server 的能力当成全量能力
        TreeSet<String> union = new TreeSet<String>();
        for (String server : controller.getServers()) {
            controller.setServer(server);
            assertFalse(controller.getShellTools().isEmpty(), server + " 没有任何可用工具");
            union.addAll(controller.getShellTools());
        }
        assertTrue(union.containsAll(ALL_SHELL_TOOLS),
                "缺少内置 shelltool：" + difference(ALL_SHELL_TOOLS, union));
    }

    @Test
    void fullStackGeneratesAMemShell() {
        MemShellFormState state = new MemShellFormState();
        state.setServer(Server.Tomcat);
        state.setServerVersion("Unknown");
        state.setShellTool(ShellTool.Godzilla);
        state.setShellType(ShellType.FILTER);
        state.setPackingMethod(Packers.DefaultBase64);

        DesktopMemShellGenerateResult result = new GenerationService().generate(state);

        assertFalse(result.getMemShellResult().getShellBytesBase64Str().isEmpty());
        assertFalse(result.getMemShellResult().getInjectorBytesBase64Str().isEmpty());
        assertFalse(result.getPackResult().isEmpty(), "打包器（memshell-party-packer）应当已装配");
    }

    @Test
    void packerCatalogIsAvailableForTheUi() {
        // 结果区的「打包」页签靠它渲染；packer 是可选运行期依赖，完整发行版显式装配了它
        MemShellFormController controller = controller();
        assertFalse(controller.getFilteredPackers().isEmpty());
        assertFalse(controller.getParamOptions(ShellTool.Command, "encryptor").isEmpty());
    }

    private static MemShellFormController controller() {
        return new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
    }

    /**
     * @return 期望存在但实际没有的项（断言失败时直接指出缺了谁）
     */
    private static List<String> difference(Collection<String> expected, Collection<String> actual) {
        List<String> missing = new ArrayList<String>(expected);
        missing.removeAll(actual);
        return missing;
    }
}
