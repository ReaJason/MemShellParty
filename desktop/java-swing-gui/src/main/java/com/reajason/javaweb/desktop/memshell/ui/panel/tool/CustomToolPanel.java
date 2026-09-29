package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.Timer;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.util.Base64;

/**
 * Custom：base64 文本域 ⇄ .class 文件两种输入；400ms 防抖自动解析类名填入内存马类名。
 */
public class CustomToolPanel extends AbstractToolPanel {
    public static final String MODE_BASE64 = "base64";
    public static final String MODE_FILE = "file";

    private final CustomClassNameParser parser;
    private final JRadioButton base64Radio = new JRadioButton("Base64");
    private final JRadioButton fileRadio = new JRadioButton(".class 文件");
    private final JTextArea base64Area = new JTextArea(6, 40);
    private final JButton chooseFileButton = new JButton("选择 .class 文件...");
    private final JLabel chosenFileLabel = new JLabel("");
    private final JLabel parsedNameLabel = new JLabel("");
    private final Timer parseTimer;
    private byte[] fileBytes;

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
        add(new JScrollPane(base64Area), "span 2, growx, wrap, hidemode 3");

        JPanel fileRow = new JPanel(new MigLayout("insets 0, fillx", "[]8[grow,fill]", "[]"));
        fileRow.add(chooseFileButton);
        fileRow.add(chosenFileLabel, "growx");
        add(fileRow, "span 2, growx, wrap, hidemode 3");

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
                controller.setShellClassBase64(base64Area.getText());
                parseTimer.restart();
            }
        });
        chooseFileButton.addActionListener(e -> chooseClassFile());

        applyModeVisibility(controller.getState().getCustomInputMode());
    }

    private void chooseClassFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setFileFilter(new FileNameExtensionFilter("Java class 文件 (*.class)", "class"));
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        try {
            fileBytes = Files.readAllBytes(file.toPath());
            String base64 = Base64.getEncoder().encodeToString(fileBytes);
            chosenFileLabel.setText(file.getName() + " (" + fileBytes.length + " bytes)");
            controller.setShellClassBase64(base64);
            parseAndFillClassName();
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "读取文件失败: " + ex.getMessage());
        }
    }

    private void parseAndFillClassName() {
        MemShellFormState s = controller.getState();
        String base64 = s.getShellClassBase64();
        if (base64 == null || base64.trim().isEmpty()) {
            parsedNameLabel.setText("");
            return;
        }
        try {
            String className = parser.parseClassNameFromBase64(base64);
            controller.setShellClassName(className);
            // 类名字段在核心配置面板，刷新让其回填解析结果（refresh 会清空解析提示，需先刷后设）
            refreshAll.run();
            parsedNameLabel.setText("解析类名: " + className);
        } catch (Exception ignored) {
            // 输入未完成时静默，对齐 web 端行为
            parsedNameLabel.setText("");
        }
    }

    private void applyModeVisibility(String mode) {
        boolean isBase64 = MODE_BASE64.equals(mode);
        base64Area.getParent().setVisible(isBase64);
        chosenFileLabel.getParent().setVisible(!isBase64);
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
            parsedNameLabel.setText("");
        } finally {
            updating = false;
        }
        applyModeVisibility(controller.getState().getCustomInputMode());
    }
}
