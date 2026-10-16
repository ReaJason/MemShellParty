package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.service.ClassBytesDecoder;
import com.reajason.javaweb.desktop.memshell.service.CfrDecompileService;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.FrameShortcutUtil;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JRootPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.WindowConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.io.File;
import java.nio.file.Files;
import java.util.concurrent.ExecutionException;

/**
 * CFR 反编译工具：进「Base64 / GzipBase64 文本」或「.class 文件」，出 Java 源码。
 * 与两个生成器界面同构 —— 独立窗口自带窗口属性与 Ctrl/⌘ + Enter 快捷键；
 * 宿主取 {@link #getRootPanel()} 嵌进自己的页签，用 {@link #setStatusReporter} 接状态出口。
 *
 * <p>输入形态不用用户挑：解码时按 gzip 魔数自动判断要不要先解压，
 * 识别出的类名与大小显示在输入行右侧；粘贴或选文件后自动反编译一次（去抖 400ms），
 * 「反编译」按钮（Ctrl/⌘ + Enter）可以随时重跑。反编译在后台线程跑，期间输入变了就丢弃在途结果。
 */
public class DecompileFrame extends JFrame {

    public static final String MODE_BASE64 = "base64";
    public static final String MODE_FILE = "file";

    /**
     * 反编译中的按钮文案：与常态文案取最大宽度固定按钮尺寸，避免「反编译 ↔ 反编译中…」切换时按钮抖动。
     */
    private static final String BUSY_LABEL = "反编译中…";
    private static final String DECOMPILE_LABEL = "反编译";
    private static final String SHORTCUT_ACTION_KEY = "decompileClass";
    /**
     * 输入去抖：粘贴/编辑停顿后才解析并反编译，连续输入不会一路跑 CFR。
     */
    private static final int INPUT_DEBOUNCE_MS = 400;

    private static final StatusReporter NO_OP_REPORTER = new StatusReporter() {
        @Override
        public void report(String message, StatusReporter.Level level) {
        }
    };

    private final ClassBytesDecoder decoder = new ClassBytesDecoder();
    private final CfrDecompileService decompileService = new CfrDecompileService();

    private final JRadioButton base64Radio = new JRadioButton("Base64 / GzipBase64");
    private final JRadioButton fileRadio = new JRadioButton(".class 文件");
    private final JTextArea base64Area = createInputArea();
    private final JScrollPane base64Scroll = new JScrollPane(base64Area);
    private final JButton chooseFileButton = SwingUiUtil.actionButton("选择 .class 文件...");
    private final JLabel chosenFileLabel = new JLabel("");
    private final JPanel fileRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[]8[grow,fill]", "[]"));
    private final JLabel inputHintLabel = new JLabel("");
    private final JButton decompileButton = SwingUiUtil.actionButton(DECOMPILE_LABEL);
    private final JLabel sourceNameLabel = new JLabel("");
    private final JTextArea sourceArea = createSourceArea();
    private final JPanel resultStack = new JPanel(new CardLayout());
    private final JButton copyButton = SwingUiUtil.actionButton("复制");
    private final JButton saveButton = new JButton("保存 .java");
    private final Timer inputTimer;

    private StatusReporter statusReporter = NO_OP_REPORTER;
    private JPanel rootPanel;
    /** 最近一次成功解码的输入：反编译按钮与「重新反编译」用它，输入变了就作废。 */
    private ClassBytesDecoder.DecodedClass currentInput;
    /** 文件模式下当前选中的文件（null = 还没选），读取/重试用它。 */
    private File chosenFile;
    /** 显示中的源码对应的类名（保存文件名用），与 {@link #currentInput} 分开跟：占位/错误文本不参与。 */
    private String displayedClassName;
    /** 源码区当前是不是「正在反编译…」占位文本：输入变成非法时要把它换掉，不能留一句"正在反编译"挂在那。 */
    private boolean sourceIsPlaceholder;
    /** 输入令牌：输入变了/新请求开始都 +1，在途结果失配即丢弃。 */
    private long decompileGeneration;

    public DecompileFrame() {
        this(true);
    }

    /**
     * @param standalone {@code true} = 独立窗口：自带 EXIT_ON_CLOSE、按屏幕自适应尺寸、
     *                   默认按钮与 Ctrl/⌘ + Enter 挂在自己的 rootPane 上；
     *                   {@code false} = 界面归宿主：不设窗口属性（本窗口不会显示），
     *                   宿主取 {@link #getRootPanel()} 自己布局。
     */
    public DecompileFrame(boolean standalone) {
        super("CFR 反编译工具 · MemShellParty v" + AppVersion.get());
        this.inputTimer = new Timer(INPUT_DEBOUNCE_MS, e -> autoDecompile());
        this.inputTimer.setRepeats(false);
        wireInput();
        applyInputMode(MODE_BASE64);
        installContent(standalone);
    }

    /**
     * 状态出口：宿主自己决定怎么显示（官方发行版外壳的共享状态栏 / 自建客户端的状态行）。
     * 不设或传 {@code null} 时静默丢弃。
     */
    public void setStatusReporter(StatusReporter statusReporter) {
        this.statusReporter = statusReporter == null ? NO_OP_REPORTER : statusReporter;
    }

    /**
     * 界面内容（输入区 + 源码区），首次调用时构建、之后返回同一实例。
     * 宿主程序把它嵌进自己的页签/面板时用它。
     *
     * <p>返回的组件是同一个实例，只能有一个父容器：内嵌了就别再 {@code setVisible(true)} 本窗口。
     */
    public JPanel getRootPanel() {
        if (rootPanel == null) {
            rootPanel = buildRootPanel();
        }
        return rootPanel;
    }

    public JButton getDecompileButton() {
        return decompileButton;
    }

    /**
     * 直接灌入 Base64 / GzipBase64 文本（宿主从别处拿到类字节时的入口，等价于用户粘贴）：
     * 走同一条去抖解析 + 自动反编译路径。
     */
    public void setBase64Input(String base64Text) {
        base64Radio.setSelected(true);
        applyInputMode(MODE_BASE64);
        base64Area.setText(base64Text == null ? "" : base64Text);
    }

    /**
     * 反编译入口：按钮、快捷键、宿主程序都走它。
     */
    public void triggerDecompile() {
        if (fileRadio.isSelected()) {
            if (chosenFile == null) {
                statusReporter.report("请先选择 .class 文件", StatusReporter.Level.INFO);
                return;
            }
            if (currentInput == null) {
                // 首次读取失败/还没读完：重试一次读取
                loadChosenFile();
                return;
            }
            startDecompile(currentInput);
            return;
        }
        if (base64Area.getText().trim().isEmpty()) {
            statusReporter.report("请粘贴 Base64 / GzipBase64 文本", StatusReporter.Level.INFO);
            return;
        }
        autoDecompile();
    }

    /**
     * 把 Ctrl/⌘ + Enter 与默认按钮挂到承载本界面的 rootPane 上：独立窗口模式构造期已挂好，
     * 内嵌时由宿主在窗口就绪后调用；同一窗口里换成别的页时，让当前页的 frame 再调一次即可转移快捷键。
     *
     * @param rootPane 实际承载本界面的 rootPane（内嵌时是宿主窗口的）；为空则跳过
     */
    public void installDecompileShortcut(JRootPane rootPane) {
        FrameShortcutUtil.install(rootPane, SHORTCUT_ACTION_KEY, new Runnable() {
            @Override
            public void run() {
                triggerDecompile();
            }
        }, decompileButton);
    }

    /**
     * 撤销 {@link #installDecompileShortcut}，把快捷键与默认按钮从 rootPane 上摘掉。
     *
     * <p>宿主在反编译页之外还有别的页签时用：进入本页装、离开就卸，
     * 免得在别的页里敲 Ctrl(⌘) + Enter 误触发一次反编译。
     *
     * @param rootPane 刚才装的 rootPane；为空则跳过
     */
    public void uninstallDecompileShortcut(JRootPane rootPane) {
        FrameShortcutUtil.uninstall(rootPane, SHORTCUT_ACTION_KEY, decompileButton);
    }

    private void installContent(boolean standalone) {
        setLayout(new BorderLayout());
        add(getRootPanel(), BorderLayout.CENTER);
        if (standalone) {
            setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            SwingUiUtil.sizeToScreen(this);
            setLocationRelativeTo(null);
            installDecompileShortcut(getRootPane());
        }
    }

    private JPanel buildRootPanel() {
        JPanel content = new JPanel(new BorderLayout(0, 4));
        content.add(buildInputPanel(), BorderLayout.NORTH);
        content.add(buildSourcePanel(), BorderLayout.CENTER);
        setSourceAvailable(false);
        return content;
    }

    private JPanel buildInputPanel() {
        JPanel input = new JPanel(new MigLayout("insets 4, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        input.setBorder(BorderFactory.createTitledBorder("输入"));

        // 模式 / 本次识别结果 / 反编译按钮同一行：默认就是 Base64，输入端不用先选模式，
        // 按钮跟着模式行走，不再单独占一行高度
        JPanel modeRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[][][grow,fill,shrink][]", "[]"));
        modeRow.add(base64Radio);
        modeRow.add(fileRadio);
        modeRow.add(inputHintLabel, "growx, pushx");
        modeRow.add(prepareDecompileButton(), "aligny center");
        input.add(modeRow, "growx");

        base64Area.setLineWrap(true);
        base64Area.setWrapStyleWord(true);
        input.add(base64Scroll, "growx, hidemode 3");

        fileRow.add(chooseFileButton);
        fileRow.add(chosenFileLabel, "growx");
        input.add(fileRow, "growx, hidemode 3");
        return input;
    }

    private JPanel buildSourcePanel() {
        // 组内边距与输入区一致（insets 4）；标题边框挂 tab 面板会贴边，外层按统一值补 margin
        JPanel wrap = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[][grow]"));
        wrap.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(4, 8, 8, 8),
                BorderFactory.createTitledBorder("反编译源码")));

        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[][grow,fill][][]", "[]"));
        headerRow.add(sourceNameLabel);
        headerRow.add(new JLabel(""), "growx");
        headerRow.add(copyButton);
        headerRow.add(saveButton);
        wrap.add(headerRow, "growx, wrap");

        resultStack.add(buildEmptyHint(), "empty");
        resultStack.add(new JScrollPane(sourceArea), "result");
        wrap.add(resultStack, "grow, push");

        copyButton.setToolTipText("复制反编译源码");
        copyButton.addActionListener(e -> SwingUiUtil.copyWithFeedback(copyButton, sourceArea.getText()));
        saveButton.setToolTipText("把反编译源码保存为 .java 文件");
        saveButton.addActionListener(e -> saveSource());
        return wrap;
    }

    /**
     * 空白态的引导：说明两种输入方式。启动期可见文案同样遵守「拉丁段不被 CJK 夹中间」规则
     * （见 ResultPanel 空态提示的注释：macOS 26 + JDK<26 下这种混排会污染字形缓存，整窗缺字）。
     */
    private JPanel buildEmptyHint() {
        JLabel title = new JLabel("尚未反编译");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 15f));
        title.setHorizontalAlignment(SwingConstants.CENTER);
        final JLabel hint = new JLabel("<html><div style='text-align: center;'>输入 Base64 / GzipBase64<br>"
                + "或选择编译好的类文件<br>反编译源码将在此展示，可复制或保存</div></html>");
        hint.setHorizontalAlignment(SwingConstants.CENTER);

        JPanel p = new JPanel(new MigLayout("insets 24, fill, wrap 1, align center", "[grow,fill]", "[]8[]")) {
            @Override
            public void updateUI() {
                super.updateUI();
                setBackground(sourceArea.getBackground());
                hint.setForeground(SwingUiUtil.mutedColor());
            }
        };
        p.add(title, "growx");
        p.add(hint, "growx");
        return p;
    }

    private JButton prepareDecompileButton() {
        decompileButton.setFont(decompileButton.getFont().deriveFont(Font.BOLD, 14f));
        decompileButton.setToolTipText("反编译 (Ctrl/Cmd + Enter)");
        decompileButton.addActionListener(e -> triggerDecompile());
        // 两种文案的最大宽度固定按钮尺寸（同生成按钮的做法）
        int width = 0;
        for (String text : new String[]{DECOMPILE_LABEL, BUSY_LABEL}) {
            decompileButton.setText(text);
            width = Math.max(width, decompileButton.getPreferredSize().width);
        }
        decompileButton.setText(DECOMPILE_LABEL);
        Dimension size = decompileButton.getPreferredSize();
        size.width = width;
        decompileButton.setPreferredSize(size);
        decompileButton.setMinimumSize(size);
        return decompileButton;
    }

    private void wireInput() {
        ButtonGroup group = new ButtonGroup();
        group.add(base64Radio);
        group.add(fileRadio);
        base64Radio.addActionListener(e -> applyInputMode(MODE_BASE64));
        fileRadio.addActionListener(e -> applyInputMode(MODE_FILE));
        base64Area.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                inputChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                inputChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                inputChanged();
            }
        });
        chooseFileButton.addActionListener(e -> chooseClassFile());
    }

    private void inputChanged() {
        // 输入变了：在途结果作废，按钮回到常态（否则会一直停在「反编译中…」）
        decompileGeneration++;
        decompileButton.setEnabled(true);
        decompileButton.setText(DECOMPILE_LABEL);
        inputTimer.restart();
    }

    private void applyInputMode(String mode) {
        boolean base64 = MODE_BASE64.equals(mode);
        base64Scroll.setVisible(base64);
        fileRow.setVisible(!base64);
    }

    private void chooseClassFile() {
        JFileChooser chooser = new JFileChooser(FileSaveUtil.getLastDirectory());
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setDialogTitle("选择 .class 文件");
        chooser.setFileFilter(new FileNameExtensionFilter("Java class 文件 (*.class)", "class"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        FileSaveUtil.rememberDirectory(file);
        if (file.length() > ClassBytesDecoder.MAX_CLASS_BYTES) {
            SwingUiUtil.showError(this, "文件过大：" + file.getName()
                    + "（" + file.length() / 1024 / 1024 + " MB），类字节上限 "
                    + ClassBytesDecoder.MAX_CLASS_BYTES / 1024 / 1024 + " MB");
            return;
        }
        chosenFile = file;
        // 换了文件，旧输入不再代表当前选择
        currentInput = null;
        chosenFileLabel.setText(file.getName() + " 读取中...");
        loadChosenFile();
    }

    /**
     * 后台读取选中的文件再反编译：EDT 不做磁盘 IO；读到的字节按 gzip/class 自动识别。
     */
    private void loadChosenFile() {
        final File file = chosenFile;
        if (file == null) {
            return;
        }
        final long requestToken = ++decompileGeneration;
        chooseFileButton.setEnabled(false);
        new SwingWorker<byte[], Void>() {
            @Override
            protected byte[] doInBackground() throws Exception {
                return Files.readAllBytes(file.toPath());
            }

            @Override
            protected void done() {
                chooseFileButton.setEnabled(true);
                if (requestToken != decompileGeneration) {
                    return;
                }
                byte[] bytes;
                try {
                    bytes = get();
                } catch (Exception ex) {
                    Throwable cause = ex instanceof ExecutionException && ex.getCause() != null ? ex.getCause() : ex;
                    String message = cause.getMessage() == null ? String.valueOf(cause) : cause.getMessage();
                    chosenFileLabel.setText(file.getName());
                    setInputHint("读取文件失败：" + message, true);
                    statusReporter.report("读取文件失败: " + message, StatusReporter.Level.ERROR);
                    return;
                }
                chosenFileLabel.setText(file.getName() + " (" + bytes.length + " bytes)");
                decompile(decoderOf(bytes));
            }
        }.execute();
    }

    /**
     * 输入去抖到期：解析当前 base64 文本并自动反编译一次。
     */
    private void autoDecompile() {
        if (base64Area.getText().trim().isEmpty()) {
            setInputHint("", false);
            clearPendingSource();
            return;
        }
        decompile(decoderOf(base64Area.getText()));
    }

    /**
     * 同一套「解码 → 提示/报错 → 反编译」收尾，两种输入都走它。
     */
    private void decompile(final BytesSupplier supplier) {
        ClassBytesDecoder.DecodedClass decoded;
        try {
            decoded = supplier.get();
        } catch (IllegalArgumentException ex) {
            setInputHint(ex.getMessage(), true);
            // 占位文本（"正在反编译 X …"）在输入作废后不能再挂着，换成一句实话
            if (sourceIsPlaceholder) {
                showSource("// 输入无法识别：" + ex.getMessage());
            }
            return;
        }
        setInputHint(describe(decoded), false);
        startDecompile(decoded);
    }

    private BytesSupplier decoderOf(final String base64Text) {
        return new BytesSupplier() {
            @Override
            public ClassBytesDecoder.DecodedClass get() {
                return decoder.decodeBase64(base64Text);
            }
        };
    }

    private BytesSupplier decoderOf(final byte[] rawBytes) {
        return new BytesSupplier() {
            @Override
            public ClassBytesDecoder.DecodedClass get() {
                return decoder.decodeClassBytes(rawBytes);
            }
        };
    }

    /**
     * 后台跑 CFR：期间源码区显示占位文本；完成后写回源码。
     * 反编译期间用户可能又改了输入：令牌失配则丢弃过期结果，不污染新输入的视图。
     */
    private void startDecompile(final ClassBytesDecoder.DecodedClass input) {
        currentInput = input;
        displayedClassName = input.getClassName();
        sourceNameLabel.setText(input.getClassName() + ".java");
        final long requestToken = ++decompileGeneration;
        final long startTime = System.currentTimeMillis();
        decompileButton.setEnabled(false);
        decompileButton.setText(BUSY_LABEL);
        statusReporter.report(BUSY_LABEL, StatusReporter.Level.BUSY);
        showSource("// 正在使用 CFR 反编译 " + input.getClassName() + " ...", true);

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return decompileService.decompile(input.getClassName(), input.getClassBytes());
            }

            @Override
            protected void done() {
                if (requestToken != decompileGeneration) {
                    return;
                }
                decompileButton.setEnabled(true);
                decompileButton.setText(DECOMPILE_LABEL);
                try {
                    showSource(get());
                    statusReporter.report("反编译成功 · " + input.getClassName()
                            + " · 耗时 " + (System.currentTimeMillis() - startTime) + " ms", StatusReporter.Level.SUCCESS);
                } catch (Exception ex) {
                    Throwable cause = ex instanceof ExecutionException && ex.getCause() != null ? ex.getCause() : ex;
                    String message = cause.getMessage() == null ? String.valueOf(cause) : cause.getMessage();
                    showSource("// 反编译失败: " + message);
                    statusReporter.report("反编译失败: " + message, StatusReporter.Level.ERROR);
                }
            }
        }.execute();
    }

    private void showSource(String source) {
        showSource(source, false);
    }

    /**
     * @param placeholder 源码区显示的是「正在反编译…」占位文本（不是结果）：
     *                    输入作废时要把它换掉/收回，不能留一句"正在反编译"挂在那
     */
    private void showSource(String source, boolean placeholder) {
        sourceIsPlaceholder = placeholder;
        sourceArea.setText(source);
        sourceArea.setCaretPosition(0);
        setSourceAvailable(true);
    }

    /**
     * 输入被清空后收回占位态：已经拿到的源码留在原地（还能复制/保存），只把"正在反编译"撤下。
     */
    private void clearPendingSource() {
        if (!sourceIsPlaceholder) {
            return;
        }
        sourceIsPlaceholder = false;
        sourceArea.setText("");
        sourceNameLabel.setText("");
        displayedClassName = null;
        setSourceAvailable(false);
    }

    private void setSourceAvailable(boolean available) {
        copyButton.setEnabled(available);
        saveButton.setEnabled(available);
        ((CardLayout) resultStack.getLayout()).show(resultStack, available ? "result" : "empty");
    }

    private void setInputHint(String text, boolean error) {
        inputHintLabel.setForeground(error ? SwingUiUtil.errorColor() : SwingUiUtil.mutedColor());
        inputHintLabel.setText(text);
    }

    private static String describe(ClassBytesDecoder.DecodedClass decoded) {
        if (decoded.isGzipped()) {
            return decoded.getClassName() + " · GzipBase64 " + decoded.getEncodedSize()
                    + " bytes, class " + decoded.getClassBytes().length + " bytes";
        }
        return decoded.getClassName() + " · class " + decoded.getClassBytes().length + " bytes";
    }

    private void saveSource() {
        String source = sourceArea.getText();
        // 占位/错误文本以 // 开头（CFR 正常产物以 /* 开头），视为不可保存
        if (source == null || source.trim().isEmpty() || source.trim().startsWith("//")) {
            statusReporter.report("没有可保存的反编译结果", StatusReporter.Level.INFO);
            return;
        }
        try {
            File file = FileSaveUtil.saveText(this, FileSaveUtil.simpleFileName(displayedClassName, ".java"), source, "java");
            if (file != null) {
                statusReporter.report("已保存：" + file.getAbsolutePath(), StatusReporter.Level.SUCCESS);
            }
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
        }
    }

    private static JTextArea createInputArea() {
        JTextArea area = new JTextArea(8, 40);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    /**
     * 源码区不换行：保留原始缩进，长了横向滚动。
     */
    private static JTextArea createSourceArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    /**
     * 输入解码的延迟求值：解码失败抛 {@link IllegalArgumentException}，由 {@link #decompile} 统一收尾。
     */
    private interface BytesSupplier {
        ClassBytesDecoder.DecodedClass get();
    }
}
