package tomcat;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.config.GenerateResult;
import com.reajason.javaweb.config.GodzillaShellConfig;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.packer.JspPacker;
import godzilla.BaseGodzillaTest;

/**
 * @author ReaJason
 * @since 2024/11/28
 */
public interface GodzillaTest extends BaseGodzillaTest {

    default String generateGodzillaJsp(GodzillaShellConfig config, String shellType) {
        Server server = Server.TOMCAT;
        ShellTool shellTool = ShellTool.Godzilla;
        GenerateResult generateResult = GeneratorMain.generate(server, shellTool, shellType, config);
        JspPacker jspPacker = new JspPacker();
        return new String(jspPacker.pack(generateResult));
    }

    default String generateGodzillaJsp(GodzillaShellConfig config, String shellType, int targetJdkVersion) {
        Server server = Server.TOMCAT;
        ShellTool shellTool = ShellTool.Godzilla;
        GenerateResult generateResult = GeneratorMain.generate(server, shellTool, shellType, config, targetJdkVersion);
        JspPacker jspPacker = new JspPacker();
        return new String(jspPacker.pack(generateResult));
    }
}
