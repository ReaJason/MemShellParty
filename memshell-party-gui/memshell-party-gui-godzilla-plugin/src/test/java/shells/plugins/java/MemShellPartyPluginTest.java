package shells.plugins.java;

import com.reajason.javaweb.desktop.memshell.ui.panel.PackageConfigPanel;
import core.annotation.PluginAnnotation;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 按 Godzilla 的加载方式检查入口类：注解、payload 绑定与内嵌的 SDK 生成器界面。
 */
class MemShellPartyPluginTest {

    @Test
    void declaresGodzillaPluginAnnotation() {
        PluginAnnotation annotation = MemShellParty.class.getAnnotation(PluginAnnotation.class);
        assertNotNull(annotation);
        assertEquals("JavaDynamicPayload", annotation.payloadName());
        assertEquals("MemShellParty", annotation.Name());
        assertNotEquals("", annotation.DisplayName());
    }

    /**
     * MemShellGeneratorFrame 是 JFrame（standalone=false 也要有显示环境才能构造），
     * CI 的 headless 环境跳过；本机/Godzilla 宿主里会完整走一遍。
     */
    @Test
    void buildsSdkGeneratorFrameView() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless());

        final MemShellParty[] holder = new MemShellParty[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                holder[0] = new MemShellParty();
            }
        });
        final MemShellParty plugin = holder[0];
        try {
            final JPanel[] viewHolder = new JPanel[1];
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    viewHolder[0] = plugin.getView();
                }
            });
            assertNotNull(viewHolder[0]);
            // SDK 生成器 rootPanel + 插件自己的状态行
            assertEquals(2, viewHolder[0].getComponentCount());
            // 注入场景不需要打包选择：无打包模式不装配打包配置条
            assertNull(find(viewHolder[0], PackageConfigPanel.class));
        } finally {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    plugin.close();
                }
            });
        }
    }

    private static <T extends Component> T find(Container root, Class<T> type) {
        for (Component child : root.getComponents()) {
            if (type.isInstance(child)) {
                return type.cast(child);
            }
            if (child instanceof Container) {
                T found = find((Container) child, type);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
