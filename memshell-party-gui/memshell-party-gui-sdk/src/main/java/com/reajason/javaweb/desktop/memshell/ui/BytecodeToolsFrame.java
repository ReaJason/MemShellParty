package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.service.BytecodeToolService;
import com.reajason.javaweb.desktop.memshell.service.ClassBytesDecoder;
import com.reajason.javaweb.desktop.memshell.service.ClassBytesEncoder;
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
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JRootPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
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
 * 字节码工具：上下布局，上面填 Base64/GzipBase64 文本或 .class 文件（可查看反编译源码），
 * 中间选工具与选项，下面输出改写后的 Base64（可复制、下载 .class、查看反编译源码）。
 *
 * <p>工具只是把输入类字节交给 {@link BytecodeToolService} 改写，再按输出格式编码；
 * 输入变化去抖 400ms 后自动重跑，选项变化立即重跑。反编译只在「查看源码」时触发。
 *
 * <p>与另外几个界面同构：独立窗口自带窗口属性与 Ctrl/⌘ + Enter；宿主取
 * {@link #getRootPanel()} 内嵌，用 {@link #setStatusReporter} 接状态出口。
 */
public class BytecodeToolsFrame extends JFrame {

    public static final String MODE_BASE64 = "base64";
    public static final String MODE_FILE = "file";

    public static final int TOOL_CONVERT = 0;
    public static final int TOOL_CLASS_INFO = 1;
    public static final int TOOL_ADD_MAIN = 2;
    public static final int TOOL_RENAME_SHRINK = 3;
    public static final int TOOL_MODULE_BYPASS = 4;
    public static final int TOOL_STATIC_TRIGGER = 5;

    private static final String[] TOOL_NAMES = {
            "转换格式",
            "修改类信息",
            "添加入口方法",
            "随机类名与瘦身",
            "模块限制绕过",
            "静态初始化触发"
    };

    private static final String FORMAT_BASE64 = "Base64";
    private static final String FORMAT_GZIP_BASE64 = "GzipBase64";

    private static final String CONSTRUCTOR_AUTO = "自动选择";
    private static final String CONSTRUCTOR_NO_ARG = "无参构造";
    private static final String CONSTRUCTOR_ARGS_FIRST = "取命令行参数";
    private static final String CONSTRUCTOR_LITERAL = "自定义字符串";

    private static final String TRIGGER_CONSTRUCTOR = "调用构造方法";
    private static final String TRIGGER_TO_STRING = "调用 toString()";

    private static final String SHORTCUT_ACTION_KEY = "bytecodeTransform";
    private static final String TRANSFORM_LABEL = "生成 Base64";
    private static final int INPUT_DEBOUNCE_MS = 400;

    private static final String CARD_CONVERT = "convert";
    private static final String CARD_CLASS_INFO = "classInfo";
    private static final String CARD_ADD_MAIN = "addMain";
    private static final String CARD_RENAME_SHRINK = "renameShrink";
    private static final String CARD_MODULE_BYPASS = "moduleBypass";
    private static final String CARD_STATIC_TRIGGER = "staticTrigger";

    private static final StatusReporter NO_OP_REPORTER = new StatusReporter() {
        @Override
        public void report(String message, StatusReporter.Level level) {
        }
    };

    private final ClassBytesDecoder decoder = new ClassBytesDecoder();
    private final BytecodeToolService toolService = new BytecodeToolService();
    private final CfrDecompileService decompileService = new CfrDecompileService();

    private final JRadioButton base64Radio = new JRadioButton("Base64 / GzipBase64");
    private final JRadioButton fileRadio = new JRadioButton(".class 文件");
    private final JTextArea base64Area = createInputArea();
    private final JScrollPane base64Scroll = new JScrollPane(base64Area);
    private final JButton chooseFileButton = SwingUiUtil.actionButton("选择 .class 文件...");
    private final JLabel chosenFileLabel = new JLabel("");
    private final JPanel fileRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[]8[grow,fill]", "[]"));
    private final JLabel inputHintLabel = new JLabel("");
    private final JButton inputSourceButton = SwingUiUtil.actionButton("查看源码");
    private final JButton transformButton = SwingUiUtil.actionButton(TRANSFORM_LABEL);

    private final JComboBox<String> toolCombo = new JComboBox<String>(TOOL_NAMES);
    private final JComboBox<String> formatCombo = new JComboBox<String>(
            new String[]{FORMAT_BASE64, FORMAT_GZIP_BASE64});
    private final JPanel optionsStack = new JPanel(new CardLayout());

    private final JTextField superClassField = new JTextField();
    private final JTextField relocateFromField = new JTextField();
    private final JTextField relocateToField = new JTextField();

    private final JComboBox<String> mainMethodCombo = new JComboBox<String>(new String[]{"main", "_main"});
    private final JComboBox<String> mainConstructorCombo = new JComboBox<String>(new String[]{
            CONSTRUCTOR_AUTO, CONSTRUCTOR_NO_ARG, CONSTRUCTOR_ARGS_FIRST, CONSTRUCTOR_LITERAL});
    private final JTextField mainLiteralField = new JTextField();

    private final JCheckBox randomNameCheck = new JCheckBox("随机类名");
    private final JTextField newClassNameField = new JTextField();
    private final JTextField newPackageField = new JTextField();
    private final JCheckBox stripDebugCheck = new JCheckBox("清除调试信息");

    private final JComboBox<String> triggerModeCombo = new JComboBox<String>(new String[]{
            TRIGGER_CONSTRUCTOR, TRIGGER_TO_STRING});
    private final JComboBox<String> triggerConstructorCombo = new JComboBox<String>(new String[]{
            CONSTRUCTOR_AUTO, CONSTRUCTOR_NO_ARG, CONSTRUCTOR_LITERAL});
    private final JTextField triggerLiteralField = new JTextField();

    private final JLabel outputNameLabel = new JLabel("");
    private final JButton sourceToggleButton = SwingUiUtil.actionButton("查看源码");
    private final JButton copyButton = SwingUiUtil.actionButton("复制 Base64");
    private final JButton downloadButton = new JButton("下载 .class");
    private final JTextArea outputArea = createOutputArea();
    private final JPanel outputStack = new JPanel(new CardLayout());

    private final Timer inputTimer;
    private StatusReporter statusReporter = NO_OP_REPORTER;

    private JPanel rootPanel;
    /** 最近一次成功解析的输入（查看输入源码用）；输入变了立即作废。 */
    private ClassBytesDecoder.DecodedClass inputDecoded;
    private File chosenFile;
    private byte[] chosenFileBytes;
    private long fileReadGeneration;
    private BytecodeToolService.TransformResult currentResult;
    private String sourceCache;
    private boolean showingSource;
    private long decompileGeneration;

    public BytecodeToolsFrame() {
        this(true);
    }

    /**
     * @param standalone {@code true} = 独立窗口：自带 EXIT_ON_CLOSE、按屏幕自适应尺寸、
     *                   默认按钮与 Ctrl/⌘ + Enter 挂在自己的 rootPane 上；
     *                   {@code false} = 界面归宿主：不设窗口属性，宿主取 {@link #getRootPanel()} 布局。
     */
    public BytecodeToolsFrame(boolean standalone) {
        super("字节码工具 · MemShellParty v" + AppVersion.get());
        this.inputTimer = new Timer(INPUT_DEBOUNCE_MS, e -> applyTransform());
        this.inputTimer.setRepeats(false);
        wireInput();
        wireOptions();
        applyInputMode(MODE_BASE64);
        updateOptionAvailability();
        installContent(standalone);
    }

    /**
     * 状态出口：宿主决定怎么显示（官方发行版外壳的共享状态栏 / 自建客户端的状态行）。
     */
    public void setStatusReporter(StatusReporter statusReporter) {
        this.statusReporter = statusReporter == null ? NO_OP_REPORTER : statusReporter;
    }

    /**
     * 界面内容：输入区 + 选项 + 结果区。宿主把它嵌进自己的页签/面板时用。
     */
    public JPanel getRootPanel() {
        if (rootPanel == null) {
            rootPanel = buildRootPanel();
        }
        return rootPanel;
    }

    public JButton getTransformButton() {
        return transformButton;
    }

    /**
     * 直接灌入 Base64 / GzipBase64 文本（等价于用户粘贴），走同一条去抖路径。
     */
    public void setBase64Input(String base64Text) {
        base64Radio.setSelected(true);
        applyInputMode(MODE_BASE64);
        base64Area.setText(base64Text == null ? "" : base64Text);
    }

    /**
     * 立即执行一次转换：按钮、快捷键、宿主程序都走它。
     */
    public void triggerTransform() {
        inputTimer.stop();
        if (fileRadio.isSelected() && chosenFile == null) {
            statusReporter.report("请先选择 .class 文件", StatusReporter.Level.INFO);
            return;
        }
        if (!fileRadio.isSelected() && base64Area.getText().trim().isEmpty()) {
            statusReporter.report("请粘贴 Base64 / GzipBase64 文本", StatusReporter.Level.INFO);
            return;
        }
        applyTransform();
    }

    /**
     * 把 Ctrl/⌘ + Enter 与默认按钮挂到承载本界面的 rootPane 上。
     */
    public void installTransformShortcut(JRootPane rootPane) {
        FrameShortcutUtil.install(rootPane, SHORTCUT_ACTION_KEY, new Runnable() {
            @Override
            public void run() {
                triggerTransform();
            }
        }, transformButton);
    }

    /**
     * 撤销 {@link #installTransformShortcut}。
     */
    public void uninstallTransformShortcut(JRootPane rootPane) {
        FrameShortcutUtil.uninstall(rootPane, SHORTCUT_ACTION_KEY, transformButton);
    }

    // ------------------------------------------------------------------------------------
    // 布局
    // ------------------------------------------------------------------------------------

    private void installContent(boolean standalone) {
        setLayout(new BorderLayout());
        add(getRootPanel(), BorderLayout.CENTER);
        if (standalone) {
            setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            SwingUiUtil.sizeToScreen(this);
            setLocationRelativeTo(null);
            installTransformShortcut(getRootPane());
        }
    }

    private JPanel buildRootPanel() {
        JPanel content = new JPanel(new MigLayout("insets 0, fill, wrap 1, gapy 4", "[grow,fill]", "[]4[]4[grow,fill]"));
        content.add(buildInputPanel(), "growx");
        content.add(buildOptionsPanel(), "growx");
        content.add(buildOutputPanel(), "grow, push");
        return content;
    }

    private JPanel buildInputPanel() {
        JPanel input = new JPanel(new MigLayout("insets 4, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        input.setBorder(BorderFactory.createTitledBorder("输入"));

        JPanel modeRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[][][grow,fill,shrink][][]", "[]"));
        modeRow.add(base64Radio);
        modeRow.add(fileRadio);
        modeRow.add(inputHintLabel, "growx, pushx, wmin 0");
        modeRow.add(inputSourceButton, "aligny center");
        modeRow.add(prepareTransformButton(), "aligny center");
        input.add(modeRow, "growx");

        // Base64 是超长单词：换行时字符级断行会触发 macOS 字形缓存污染（整窗拉丁字形随机丢失），
        // 输入/输出都改为横向滚动；反编译源码有空格，仍用换行。
        input.add(base64Scroll, "growx, hidemode 3, h 110!");

        fileRow.add(chooseFileButton);
        fileRow.add(chosenFileLabel, "growx, wmin 0");
        input.add(fileRow, "growx, hidemode 3");
        return input;
    }

    private JPanel buildOptionsPanel() {
        JPanel options = new JPanel(new MigLayout("insets 4, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        options.setBorder(BorderFactory.createTitledBorder("工具与选项"));

        JPanel toolRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[][220!][][120!][grow,fill]", "[]"));
        toolRow.add(new JLabel("工具"));
        toolRow.add(toolCombo, "w 220!");
        toolRow.add(new JLabel("输出格式"));
        toolRow.add(formatCombo, "w 120!");
        toolRow.add(new JLabel(""), "growx");
        options.add(toolRow, "growx");

        optionsStack.add(buildConvertOptions(), CARD_CONVERT);
        optionsStack.add(buildClassInfoOptions(), CARD_CLASS_INFO);
        optionsStack.add(buildAddMainOptions(), CARD_ADD_MAIN);
        optionsStack.add(buildRenameShrinkOptions(), CARD_RENAME_SHRINK);
        optionsStack.add(buildModuleBypassOptions(), CARD_MODULE_BYPASS);
        optionsStack.add(buildStaticTriggerOptions(), CARD_STATIC_TRIGGER);
        options.add(optionsStack, "growx");
        // 宿主可能在 getRootPanel() 之前就改过工具下拉框：卡片建好后按当前选择补一次
        updateToolCard();
        return options;
    }

    private JPanel buildConvertOptions() {
        return hintPanel("不做改写，按所选输出格式重新编码；主要用于文本与类文件的互转。");
    }

    private JPanel buildClassInfoOptions() {
        JPanel p = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[][grow,fill][][grow,fill]", "[]"));
        p.add(new JLabel("新父类"));
        superClassField.putClientProperty("JTextField.placeholderText",
                "留空不修改，例如 com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
        // 父类名很长：输入框占大半行，包名替换挪到第二行
        p.add(superClassField, "growx, span 3, wrap");

        p.add(new JLabel("包名替换"));
        JPanel relocateRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[grow,fill]6[]6[grow,fill]", "[]"));
        relocateFromField.putClientProperty("JTextField.placeholderText", "javax.servlet");
        relocateToField.putClientProperty("JTextField.placeholderText", "jakarta.servlet");
        relocateRow.add(relocateFromField, "growx");
        relocateRow.add(new JLabel("替换为"));
        relocateRow.add(relocateToField, "growx");
        p.add(relocateRow, "growx, span 3");
        return p;
    }

    private JPanel buildAddMainOptions() {
        JPanel p = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[][grow,fill][][grow,fill]", "[]"));
        p.add(new JLabel("方法名"));
        p.add(mainMethodCombo, "growx");
        p.add(new JLabel("构造方式"));
        p.add(mainConstructorCombo, "growx");
        p.add(new JLabel("字符串参数"));
        mainLiteralField.putClientProperty("JTextField.placeholderText", "自定义字符串参数");
        p.add(mainLiteralField, "growx, span 3");
        return p;
    }

    private JPanel buildRenameShrinkOptions() {
        JPanel p = new JPanel(new MigLayout("insets 0, fillx, gapx 8, wrap 2", "[][grow,fill][]", "[]"));
        JPanel checks = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[][]", "[]"));
        randomNameCheck.setSelected(true);
        stripDebugCheck.setSelected(true);
        randomNameCheck.setToolTipText("生成随机简单类名，抹掉原类名");
        stripDebugCheck.setToolTipText("清掉 SourceFile、行号、局部变量等可被溯源的调试信息");
        checks.add(randomNameCheck);
        checks.add(stripDebugCheck);
        p.add(checks, "span 2, growx, wrap");

        p.add(new JLabel("新类名"));
        newClassNameField.putClientProperty("JTextField.placeholderText", "留空保持原名，可填完整类名");
        p.add(newClassNameField, "growx, wrap");

        p.add(new JLabel("新包名"));
        newPackageField.putClientProperty("JTextField.placeholderText", "留空保持原包名");
        p.add(newPackageField, "growx");
        return p;
    }

    private JPanel buildModuleBypassOptions() {
        // 不在文案里写 JDK 9+：拉丁段夹在 CJK 中间会触发 macOS 字形缓存污染
        return hintPanel("静态初始化时把当前类并入基础模块，绕过模块访问限制，旧版本虚拟机可能不支持。");
    }

    private JPanel buildStaticTriggerOptions() {
        JPanel p = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[][grow,fill][][grow,fill]", "[]"));
        p.add(new JLabel("触发方式"));
        p.add(triggerModeCombo, "growx");
        p.add(new JLabel("构造方式"));
        p.add(triggerConstructorCombo, "growx");
        p.add(new JLabel("字符串参数"));
        triggerLiteralField.putClientProperty("JTextField.placeholderText", "自定义字符串参数");
        p.add(triggerLiteralField, "growx, span 3");
        return p;
    }

    private JPanel buildOutputPanel() {
        // 组内边距与输入区一致（insets 4）；标题边框挂内容面板会贴边，外层补 margin
        JPanel wrap = new JPanel(new MigLayout("insets 4, fill, wrap 1", "[grow,fill]", "[][grow]"));
        wrap.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(4, 8, 8, 8),
                BorderFactory.createTitledBorder("生成结果")));

        JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 6", "[grow,fill][][][]", "[]"));
        headerRow.add(outputNameLabel, "growx, pushx, wmin 0");
        headerRow.add(sourceToggleButton);
        headerRow.add(copyButton);
        headerRow.add(downloadButton);
        wrap.add(headerRow, "growx, wrap");

        outputStack.add(buildEmptyHint(), "empty");
        outputStack.add(new JScrollPane(outputArea), "result");
        wrap.add(outputStack, "grow, push");

        sourceToggleButton.setToolTipText("在 Base64 与 CFR 反编译源码之间切换");
        sourceToggleButton.addActionListener(e -> toggleSourceView());
        copyButton.setToolTipText("复制当前输出文本");
        copyButton.addActionListener(e -> SwingUiUtil.copyWithFeedback(copyButton, encodedOutput()));
        downloadButton.setToolTipText("把改写后的类字节保存为 .class 文件");
        downloadButton.addActionListener(e -> downloadClass());
        setOutputAvailable(false);
        return wrap;
    }

    /**
     * 空态引导。启动期可见文案遵守单一边界规则（拉丁段不要被 CJK 夹在中间）。
     */
    private JPanel buildEmptyHint() {
        JLabel title = new JLabel("尚未生成");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 15f));
        title.setHorizontalAlignment(SwingConstants.CENTER);
        final JLabel hint = new JLabel("<html><div style='text-align: center;'>填入类字节并选择工具<br>"
                + "转换结果将在此展示，可复制或下载</div></html>");
        hint.setHorizontalAlignment(SwingConstants.CENTER);
        hint.setMinimumSize(new Dimension(0, hint.getPreferredSize().height));

        JPanel p = new JPanel(new MigLayout("insets 24, fill, wrap 1, align center", "[grow,fill]", "[]8[]")) {
            @Override
            public void updateUI() {
                super.updateUI();
                setBackground(outputArea.getBackground());
                hint.setForeground(SwingUiUtil.mutedColor());
            }
        };
        p.add(title, "growx");
        p.add(hint, "growx");
        return p;
    }

    private static JPanel hintPanel(String text) {
        JPanel p = new JPanel(new MigLayout("insets 2 2 2 2, fillx", "[grow,fill]", "[]"));
        JLabel label = new JLabel("<html>" + text + "</html>");
        label.setForeground(SwingUiUtil.mutedColor());
        p.add(label, "growx");
        return p;
    }

    private JButton prepareTransformButton() {
        transformButton.setFont(transformButton.getFont().deriveFont(Font.BOLD, 14f));
        transformButton.setToolTipText("按当前输入与工具生成结果 (Ctrl 或 Cmd + Enter)");
        transformButton.addActionListener(e -> triggerTransform());
        return transformButton;
    }

    // ------------------------------------------------------------------------------------
    // 输入与选项联动
    // ------------------------------------------------------------------------------------

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
        inputSourceButton.setToolTipText("反编译当前输入类，弹窗查看源码");
        inputSourceButton.setEnabled(false);
        inputSourceButton.addActionListener(e -> showInputSource());
    }

    private void wireOptions() {
        toolCombo.addActionListener(e -> {
            updateToolCard();
            updateOptionAvailability();
            triggerTransform();
        });
        formatCombo.addActionListener(e -> {
            // 格式只影响编码，不重跑改写（随机类名工具不会因此换名）
            if (currentResult != null && !showingSource) {
                renderBase64();
            }
        });
        superClassField.getDocument().addDocumentListener(optionDocumentListener());
        relocateFromField.getDocument().addDocumentListener(optionDocumentListener());
        relocateToField.getDocument().addDocumentListener(optionDocumentListener());
        mainLiteralField.getDocument().addDocumentListener(optionDocumentListener());
        newClassNameField.getDocument().addDocumentListener(optionDocumentListener());
        newPackageField.getDocument().addDocumentListener(optionDocumentListener());
        triggerLiteralField.getDocument().addDocumentListener(optionDocumentListener());

        mainMethodCombo.addActionListener(e -> triggerTransform());
        mainConstructorCombo.addActionListener(e -> {
            updateOptionAvailability();
            triggerTransform();
        });
        triggerModeCombo.addActionListener(e -> triggerTransform());
        triggerConstructorCombo.addActionListener(e -> {
            updateOptionAvailability();
            triggerTransform();
        });
        randomNameCheck.addActionListener(e -> {
            updateOptionAvailability();
            triggerTransform();
        });
        stripDebugCheck.addActionListener(e -> triggerTransform());
    }

    private DocumentListener optionDocumentListener() {
        return new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                optionChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                optionChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                optionChanged();
            }

            private void optionChanged() {
                inputTimer.restart();
            }
        };
    }

    private void updateToolCard() {
        ((CardLayout) optionsStack.getLayout()).show(optionsStack, cardForTool(toolCombo.getSelectedIndex()));
        optionsStack.revalidate();
        optionsStack.repaint();
    }

    private static String cardForTool(int index) {
        switch (index) {
            case TOOL_CLASS_INFO:
                return CARD_CLASS_INFO;
            case TOOL_ADD_MAIN:
                return CARD_ADD_MAIN;
            case TOOL_RENAME_SHRINK:
                return CARD_RENAME_SHRINK;
            case TOOL_MODULE_BYPASS:
                return CARD_MODULE_BYPASS;
            case TOOL_STATIC_TRIGGER:
                return CARD_STATIC_TRIGGER;
            case TOOL_CONVERT:
            default:
                return CARD_CONVERT;
        }
    }

    /**
     * 工具相关的子选项可用性：随机类名时类名字段不可编辑；只有「自定义字符串」才需要参数字段。
     */
    private void updateOptionAvailability() {
        boolean randomName = randomNameCheck.isSelected();
        newClassNameField.setEnabled(!randomName);
        mainLiteralField.setEnabled(CONSTRUCTOR_LITERAL.equals(mainConstructorCombo.getSelectedItem()));
        triggerLiteralField.setEnabled(CONSTRUCTOR_LITERAL.equals(triggerConstructorCombo.getSelectedItem()));
        updateToolCard();
    }

    private void applyInputMode(String mode) {
        boolean base64 = MODE_BASE64.equals(mode);
        base64Scroll.setVisible(base64);
        fileRow.setVisible(!base64);
        inputDecoded = null;
        inputSourceButton.setEnabled(false);
        if (!base64 && chosenFile == null) {
            setInputHint("请选择 .class 文件", false);
            clearOutput();
            return;
        }
        inputTimer.restart();
    }

    private void inputChanged() {
        inputDecoded = null;
        inputSourceButton.setEnabled(false);
        inputTimer.restart();
    }

    private void chooseClassFile() {
        JFileChooser chooser = new JFileChooser(FileSaveUtil.getLastDirectory());
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setDialogTitle("选择 .class 文件");
        chooser.setFileFilter(new FileNameExtensionFilter("Java class 文件 (*.class)", "class"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        final File file = chooser.getSelectedFile();
        FileSaveUtil.rememberDirectory(file);
        if (file.length() > ClassBytesDecoder.MAX_CLASS_BYTES) {
            SwingUiUtil.showError(this, "文件过大：" + file.getName()
                    + " (" + file.length() / 1024 / 1024 + " MB), 类字节上限 "
                    + ClassBytesDecoder.MAX_CLASS_BYTES / 1024 / 1024 + " MB");
            return;
        }
        chosenFile = file;
        chosenFileBytes = null;
        inputDecoded = null;
        inputSourceButton.setEnabled(false);
        chosenFileLabel.setText(file.getName() + " 读取中...");
        loadChosenFile();
    }

    private void loadChosenFile() {
        final File file = chosenFile;
        if (file == null) {
            return;
        }
        final long requestToken = ++fileReadGeneration;
        chooseFileButton.setEnabled(false);
        new SwingWorker<byte[], Void>() {
            @Override
            protected byte[] doInBackground() throws Exception {
                return Files.readAllBytes(file.toPath());
            }

            @Override
            protected void done() {
                chooseFileButton.setEnabled(true);
                if (requestToken != fileReadGeneration) {
                    return;
                }
                try {
                    chosenFileBytes = get();
                } catch (Exception ex) {
                    Throwable cause = ex instanceof ExecutionException && ex.getCause() != null ? ex.getCause() : ex;
                    String message = cause.getMessage() == null ? String.valueOf(cause) : cause.getMessage();
                    chosenFileLabel.setText(file.getName());
                    setInputHint("读取文件失败: " + message, true);
                    statusReporter.report("读取文件失败: " + message, StatusReporter.Level.ERROR);
                    return;
                }
                chosenFileLabel.setText(file.getName() + " (" + chosenFileBytes.length + " bytes)");
                triggerTransform();
            }
        }.execute();
    }

    // ------------------------------------------------------------------------------------
    // 转换与结果
    // ------------------------------------------------------------------------------------

    private void applyTransform() {
        if (fileRadio.isSelected()) {
            if (chosenFileBytes == null) {
                clearOutput();
                return;
            }
        } else if (base64Area.getText().trim().isEmpty()) {
            inputDecoded = null;
            inputSourceButton.setEnabled(false);
            setInputHint("", false);
            clearOutput();
            return;
        }

        ClassBytesDecoder.DecodedClass decoded;
        try {
            decoded = fileRadio.isSelected()
                    ? decoder.decodeClassBytes(chosenFileBytes)
                    : decoder.decodeBase64(base64Area.getText());
        } catch (IllegalArgumentException ex) {
            inputDecoded = null;
            inputSourceButton.setEnabled(false);
            setInputHint(ex.getMessage(), true);
            clearOutput();
            return;
        }
        inputDecoded = decoded;
        inputSourceButton.setEnabled(true);
        setInputHint(describe(decoded), false);

        BytecodeToolService.TransformResult result;
        try {
            result = transform(decoded.getClassBytes());
        } catch (RuntimeException ex) {
            clearOutput();
            String message = ex.getMessage() == null ? String.valueOf(ex) : ex.getMessage();
            setInputHint("转换失败: " + message, true);
            statusReporter.report("转换失败: " + message, StatusReporter.Level.ERROR);
            return;
        }
        showResult(result);
    }

    private BytecodeToolService.TransformResult transform(byte[] classBytes) {
        switch (toolCombo.getSelectedIndex()) {
            case TOOL_CLASS_INFO:
                return toolService.changeClassInfo(classBytes, superClassField.getText(),
                        relocateFromField.getText(), relocateToField.getText());
            case TOOL_ADD_MAIN:
                return toolService.addMainMethod(classBytes,
                        selectedText(mainMethodCombo), constructorMode(mainConstructorCombo),
                        mainLiteralField.getText());
            case TOOL_RENAME_SHRINK:
                return toolService.renameAndShrink(classBytes, newClassNameField.getText(),
                        newPackageField.getText(), randomNameCheck.isSelected(), stripDebugCheck.isSelected());
            case TOOL_MODULE_BYPASS:
                return toolService.addModuleBypass(classBytes);
            case TOOL_STATIC_TRIGGER:
                return toolService.addStaticTrigger(classBytes, triggerMode(),
                        constructorMode(triggerConstructorCombo), triggerLiteralField.getText());
            case TOOL_CONVERT:
            default:
                return toolService.convert(classBytes);
        }
    }

    private static String selectedText(JComboBox<String> combo) {
        Object item = combo.getSelectedItem();
        return item == null ? null : String.valueOf(item);
    }

    private static BytecodeToolService.ConstructorMode constructorMode(JComboBox<String> combo) {
        String selected = selectedText(combo);
        if (CONSTRUCTOR_NO_ARG.equals(selected)) {
            return BytecodeToolService.ConstructorMode.NO_ARG;
        }
        if (CONSTRUCTOR_ARGS_FIRST.equals(selected)) {
            return BytecodeToolService.ConstructorMode.ARGS_FIRST;
        }
        if (CONSTRUCTOR_LITERAL.equals(selected)) {
            return BytecodeToolService.ConstructorMode.STRING_LITERAL;
        }
        return BytecodeToolService.ConstructorMode.AUTO;
    }

    private BytecodeToolService.TriggerMode triggerMode() {
        return TRIGGER_TO_STRING.equals(triggerModeCombo.getSelectedItem())
                ? BytecodeToolService.TriggerMode.TO_STRING
                : BytecodeToolService.TriggerMode.CONSTRUCTOR;
    }

    private void showResult(BytecodeToolService.TransformResult result) {
        currentResult = result;
        sourceCache = null;
        showingSource = false;
        decompileGeneration++;
        if (sourceToggleButton != null) {
            sourceToggleButton.setText("查看源码");
        }
        outputNameLabel.setText(result.getClassName() + " (" + result.getSize() + " bytes)");
        outputNameLabel.setToolTipText(outputNameLabel.getText());
        renderBase64();
        setOutputAvailable(true);
        // 状态栏只报纯 CJK 结果：类名 / 大小已经在输出标题里，混排长串会触发 macOS
        // 字形缓存污染（整窗拉丁字形随机丢失），文案约定见 ResultPanel 空态提示注释。
        statusReporter.report("转换成功", StatusReporter.Level.SUCCESS);
    }

    private void renderBase64() {
        if (currentResult == null) {
            return;
        }
        setOutputText(encodedOutput(), false);
    }

    private String encodedOutput() {
        if (currentResult == null) {
            return "";
        }
        boolean gzip = FORMAT_GZIP_BASE64.equals(formatCombo.getSelectedItem());
        return ClassBytesEncoder.encode(currentResult.getClassBytes(), gzip);
    }

    private void clearOutput() {
        currentResult = null;
        sourceCache = null;
        showingSource = false;
        decompileGeneration++;
        outputArea.setText("");
        outputNameLabel.setText("");
        outputNameLabel.setToolTipText(null);
        if (sourceToggleButton != null) {
            sourceToggleButton.setText("查看源码");
        }
        setOutputAvailable(false);
    }

    private void setOutputAvailable(boolean available) {
        sourceToggleButton.setEnabled(available);
        copyButton.setEnabled(available);
        downloadButton.setEnabled(available);
        ((CardLayout) outputStack.getLayout()).show(outputStack, available ? "result" : "empty");
    }

    private void toggleSourceView() {
        if (currentResult == null) {
            return;
        }
        if (showingSource) {
            showingSource = false;
            decompileGeneration++;
            sourceToggleButton.setText("查看源码");
            renderBase64();
            return;
        }
        showingSource = true;
        sourceToggleButton.setText("查看 Base64");
        if (sourceCache != null) {
            setOutputText(sourceCache, true);
            return;
        }
        final BytecodeToolService.TransformResult result = currentResult;
        final long requestToken = ++decompileGeneration;
        setOutputText("// 正在使用 CFR 反编译 " + result.getClassName() + " ...", true);
        statusReporter.report("正在反编译", StatusReporter.Level.BUSY);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return decompileService.decompile(result.getClassName(), result.getClassBytes());
            }

            @Override
            protected void done() {
                if (requestToken != decompileGeneration || result != currentResult) {
                    return;
                }
                try {
                    sourceCache = get();
                    statusReporter.report("反编译成功", StatusReporter.Level.SUCCESS);
                } catch (Exception ex) {
                    Throwable cause = ex instanceof ExecutionException && ex.getCause() != null ? ex.getCause() : ex;
                    String message = cause.getMessage() == null ? String.valueOf(cause) : cause.getMessage();
                    sourceCache = "// 反编译失败: " + message;
                    statusReporter.report("反编译失败: " + message, StatusReporter.Level.ERROR);
                }
                if (showingSource) {
                    setOutputText(sourceCache, true);
                }
            }
        }.execute();
    }

    private void showInputSource() {
        final ClassBytesDecoder.DecodedClass decoded;
        try {
            decoded = inputDecoded != null ? inputDecoded : decodeCurrentInput();
        } catch (IllegalArgumentException ex) {
            setInputHint(ex.getMessage(), true);
            return;
        }
        inputSourceButton.setEnabled(false);
        statusReporter.report("正在反编译输入类", StatusReporter.Level.BUSY);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return decompileService.decompile(decoded.getClassName(), decoded.getClassBytes());
            }

            @Override
            protected void done() {
                inputSourceButton.setEnabled(true);
                try {
                    String source = get();
                    new SourceViewDialog(BytecodeToolsFrame.this, "输入源码 · "
                            + decoded.getClassName(), decoded.getClassName(), source).setVisible(true);
                    statusReporter.report("反编译成功", StatusReporter.Level.SUCCESS);
                } catch (Exception ex) {
                    Throwable cause = ex instanceof ExecutionException && ex.getCause() != null ? ex.getCause() : ex;
                    String message = cause.getMessage() == null ? String.valueOf(cause) : cause.getMessage();
                    statusReporter.report("反编译失败: " + message, StatusReporter.Level.ERROR);
                    SwingUiUtil.showError(BytecodeToolsFrame.this, "反编译失败: " + message);
                }
            }
        }.execute();
    }

    private ClassBytesDecoder.DecodedClass decodeCurrentInput() {
        if (fileRadio.isSelected()) {
            if (chosenFileBytes == null) {
                throw new IllegalArgumentException("请先选择并读取 .class 文件");
            }
            return decoder.decodeClassBytes(chosenFileBytes);
        }
        return decoder.decodeBase64(base64Area.getText());
    }

    private void downloadClass() {
        if (currentResult == null) {
            return;
        }
        try {
            String suggestedName = FileSaveUtil.simpleFileName(currentResult.getClassName(), ".class");
            File file = FileSaveUtil.saveBytes(this, suggestedName, currentResult.getClassBytes(), "class");
            if (file != null) {
                statusReporter.report("已保存：" + file.getAbsolutePath(), StatusReporter.Level.SUCCESS);
            }
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "保存失败: " + ex.getMessage());
        }
    }

    private void setInputHint(String text, boolean error) {
        inputHintLabel.setForeground(error ? SwingUiUtil.errorColor() : SwingUiUtil.mutedColor());
        inputHintLabel.setText(text);
        inputHintLabel.setToolTipText(text == null || text.isEmpty() ? null : text);
    }

    private static String describe(ClassBytesDecoder.DecodedClass decoded) {
        if (decoded.isGzipped()) {
            return decoded.getClassName() + " · GzipBase64 " + decoded.getEncodedSize()
                    + " bytes, class " + decoded.getClassBytes().length + " bytes";
        }
        return decoded.getClassName() + " · class " + decoded.getClassBytes().length + " bytes";
    }

    private static JTextArea createInputArea() {
        JTextArea area = new JTextArea(6, 40);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    private static JTextArea createOutputArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        // 默认不换行（Base64）；展示 CFR 源码时由 setOutputText 打开换行
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    /**
     * Base64 不换行（字符级断行会触发 macOS 字形缓存污染），源码有空格/换行，打开换行。
     */
    private void setOutputText(String text, boolean wrap) {
        outputArea.setLineWrap(wrap);
        outputArea.setWrapStyleWord(wrap);
        outputArea.setText(text);
        outputArea.setCaretPosition(0);
    }
}
