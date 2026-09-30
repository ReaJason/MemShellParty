package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.util.FileSaveUtil;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Map;

/**
 * Custom：base64 文本域 ⇄ .class 文件两种输入；400ms 防抖自动解析类名填入内存马类名。
 * .class 读取限 8MB 且走后台线程；解析失败在面板内给出可见反馈（不再静默）。
 */
public class CustomToolPanel extends AbstractToolPanel {
    public static final String MODE_BASE64 = "base64";
    public static final String MODE_FILE = "file";

    /**
     * 内存马 class 远超此大小即可判定选错文件；同步挡掉 EDT 大文件 IO。
     */
    private static final long MAX_CLASS_FILE_SIZE = 8L * 1024 * 1024;

    private final CustomClassNameParser parser;
    private final JRadioButton base64Radio = new JRadioButton("Base64");
    private final JRadioButton fileRadio = new JRadioButton(".class 文件");
    private final JTextArea base64Area = new JTextArea(6, 40);
    private final JScrollPane base64Scroll = new JScrollPane(base64Area);
    private final JButton chooseFileButton = new JButton("选择 .class 文件...");
    private final JLabel chosenFileLabel = new JLabel("");
    private final JPanel fileRow = new JPanel(new MigLayout("insets 0, fillx", "[]8[grow,fill]", "[]"));
    private final JLabel parsedNameLabel = new JLabel("");
    private final JLabel errorLabel = SwingUiUtil.createErrorLabel();
    private final Timer parseTimer;

    public CustomToolPanel(MemShellFormController controller, CustomClassNameParser parser, Runnable refreshAll) {
        super(controller, refreshAll);
        this.parser = parser;

        ButtonGroup group = new ButtonGroup();
        group.add(base64Radio);
        group.add(fileRadio);

        JPanel modeRow = new JPanel(new MigLayout("insets 0, fillx", "[][][grow,fill]", "[]"));
        modeRow.add(base64Radio);
        modeRow.add(fileRadio);
        modeRow.add(parsedNameLabel, "growx");
        add(modeRow, "span 2, growx, wrap");

        base64Area.setLineWrap(true);
        base64Area.setWrapStyleWord(true);
        base64Area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        add(base64Scroll, "span 2, growx, wrap, hidemode 3");

        fileRow.add(chooseFileButton);
        fileRow.add(chosenFileLabel, "growx");
        add(fileRow, "span 2, growx, wrap, hidemode 3");

        // 校验红字挂面板自身：base64 域/文件行都不是 labeled 行，沿父链找到这里
        add(errorLabel, "span 2, growx, hidemode 3");
        SwingUiUtil.attachErrorLabel(this, errorLabel);

        parseTimer = new Timer(400, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                parseAndFillClassName();
            }
        });
        parseTimer.setRepeats(false);

        base64Radio.addActionListener(e -> {
            if (updating) return;
            controller.setCustomInputMode(MODE_BASE64);
            applyModeVisibility(MODE_BASE64);
        });
        fileRadio.addActionListener(e -> {
            if (updating) return;
            controller.setCustomInputMode(MODE_FILE);
            applyModeVisibility(MODE_FILE);
        });
        base64Area.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                changed();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                changed();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                changed();
            }

            private void changed() {
                if (updating) return;
                SwingUiUtil.clearFieldError(base64Area);
                controller.setShellClassBase64(base64Area.getText());
                parseTimer.restart();
            }
        });
        chooseFileButton.addActionListener(e -> chooseClassFile());

        applyModeVisibility(controller.getState().getCustomInputMode());
    }

    private void chooseClassFile() {
        JFileChooser chooser = new JFileChooser(FileSaveUtil.getLastDirectory());
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setFileFilter(new FileNameExtensionFilter("Java class 文件 (*.class)", "class"));
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        final File file = chooser.getSelectedFile();
        FileSaveUtil.rememberDirectory(file);
        if (file.length() > MAX_CLASS_FILE_SIZE) {
            SwingUiUtil.showError(this, "文件过大：" + file.getName()
                    + "（" + file.length() / 1024 / 1024 + " MB），内存马 class 上限 8 MB");
            return;
        }
        // 后台读取，避免 EDT 磁盘 IO 卡界面
        chooseFileButton.setEnabled(false);
        chosenFileLabel.setText(file.getName() + " 读取中...");
        new SwingWorker<byte[], Void>() {
            @Override
            protected byte[] doInBackground() throws Exception {
                return Files.readAllBytes(file.toPath());
            }

            @Override
            protected void done() {
                chooseFileButton.setEnabled(true);
                try {
                    byte[] bytes = get();
                    String base64 = Base64.getEncoder().encodeToString(bytes);
                    chosenFileLabel.setText(file.getName() + " (" + bytes.length + " bytes)");
                    SwingUiUtil.clearFieldError(chooseFileButton);
                    controller.setShellClassBase64(base64);
                    parseAndFillClassName();
                } catch (Exception ex) {
                    chosenFileLabel.setText("");
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    SwingUiUtil.showError(CustomToolPanel.this, "读取文件失败: " + cause.getMessage());
                }
            }
        }.execute();
    }

    private void parseAndFillClassName() {
        MemShellFormState s = controller.getState();
        String base64 = s.getShellClassBase64();
        if (base64 == null || base64.trim().isEmpty()) {
            setParsedHint("", false);
            return;
        }
        try {
            String className = parser.parseClassNameFromBase64(base64);
            controller.setShellClassName(className);
            // 类名字段在核心配置面板，刷新让其回填解析结果（refresh 会清空解析提示，需先刷后设）
            refreshAll.run();
            setParsedHint("解析类名: " + className, false);
        } catch (Exception ex) {
            setParsedHint("解析失败：请确认输入是合法 .class 字节的 Base64", true);
        }
    }

    private void setParsedHint(String text, boolean error) {
        parsedNameLabel.setForeground(error ? SwingUiUtil.errorColor() : SwingUiUtil.mutedColor());
        parsedNameLabel.setText(text);
    }

    private void applyModeVisibility(String mode) {
        boolean isBase64 = MODE_BASE64.equals(mode);
        base64Scroll.setVisible(isBase64);
        fileRow.setVisible(!isBase64);
    }

    @Override
    public void applyValidationErrors(Map<String, String> errors) {
        super.applyValidationErrors(errors);
        String message = errors.get("shellClassBase64");
        if (message != null) {
            JComponent field = MODE_BASE64.equals(controller.getState().getCustomInputMode())
                    ? base64Area : chooseFileButton;
            SwingUiUtil.setFieldError(field, message);
        }
    }

    @Override
    public JComponent validationFocusTarget(String field) {
        if ("shellClassBase64".equals(field)) {
            return MODE_BASE64.equals(controller.getState().getCustomInputMode())
                    ? base64Area : chooseFileButton;
        }
        return super.validationFocusTarget(field);
    }

    @Override
    public void refreshFromController() {
        updating = true;
        try {
            MemShellFormState s = controller.getState();
            applyCommonState(s);
            base64Area.setText(s.getShellClassBase64());
            boolean isBase64 = MODE_BASE64.equals(s.getCustomInputMode());
            base64Radio.setSelected(isBase64);
            fileRadio.setSelected(!isBase64);
            setParsedHint("", false);
        } finally {
            updating = false;
        }
        applyModeVisibility(controller.getState().getCustomInputMode());
    }
}
