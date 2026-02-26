package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.event.ActionEvent;
import java.io.File;
import java.nio.file.Files;
import java.util.Base64;

public class CustomToolPanel extends AbstractToolPanel {
    private final CustomClassNameParser parser;
    private final JRadioButton base64Mode = new JRadioButton("Base64", true);
    private final JRadioButton fileMode = new JRadioButton("File");
    private final JTextArea base64Area = new JTextArea(4, 40);
    private final JButton fileButton = new JButton("选择 .class 文件");
    private final JLabel fileLabel = new JLabel("未选择文件");
    private final JPanel base64Panel = new JPanel(new MigLayout("insets 0, fillx", "[grow,fill]", "[grow,fill]"));
    private final JPanel filePanel = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[grow,fill][]", "[]"));
    private final Timer parseDebounce;

    public CustomToolPanel(MemShellFormController controller, CustomClassNameParser parser, Runnable refreshAll) {
        super(controller, refreshAll);
        this.parser = parser;

        ButtonGroup group = new ButtonGroup();
        group.add(base64Mode);
        group.add(fileMode);
        add(new JLabel("Shell Class"));
        JPanel radioWrap = new JPanel(new MigLayout("insets 0, gapx 8", "[][]", "[]"));
        radioWrap.add(base64Mode);
        radioWrap.add(fileMode);
        add(radioWrap, "growx, wrap");

        base64Panel.add(new JScrollPane(base64Area), "grow");
        filePanel.add(fileLabel, "growx");
        filePanel.add(fileButton);
        add(base64Panel, "span 2, growx, gapy 1 0, wrap, hidemode 3");
        add(filePanel, "span 2, growx, gapy 1 0, wrap, hidemode 3");

        addRandomClassSection();

        parseDebounce = new Timer(400, this::parseAndFillClassName);
        parseDebounce.setRepeats(false);

        base64Area.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { changed(); }
            @Override public void removeUpdate(DocumentEvent e) { changed(); }
            @Override public void changedUpdate(DocumentEvent e) { changed(); }
            private void changed() {
                if (updating) return;
                controller.setShellClassBase64(base64Area.getText());
                parseDebounce.restart();
            }
        });

        base64Mode.addActionListener(e -> {
            if (updating) return;
            controller.setCustomInputMode("base64");
            refreshAll.run();
        });
        fileMode.addActionListener(e -> {
            if (updating) return;
            controller.setCustomInputMode("file");
            refreshAll.run();
        });
        fileButton.addActionListener(this::chooseFile);
    }

    private void chooseFile(ActionEvent event) {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        File file = chooser.getSelectedFile();
        try {
            byte[] bytes = Files.readAllBytes(file.toPath());
            String base64 = Base64.getEncoder().encodeToString(bytes);
            controller.setShellClassBase64(base64);
            fileLabel.setText(file.getName());
            String className = parser.parseClassName(bytes);
            controller.setShellClassName(className);
            refreshAll.run();
        } catch (Exception ex) {
            SwingUiUtil.showError(this, "读取自定义类失败: " + ex.getMessage());
        }
    }

    private void parseAndFillClassName(ActionEvent ignored) {
        try {
            String base64 = controller.getState().getShellClassBase64();
            if (base64 == null || base64.trim().isEmpty()) return;
            String className = parser.parseClassNameFromBase64(base64);
            controller.setShellClassName(className);
            refreshAll.run();
        } catch (Exception ignoredEx) {
            // ignore parse errors while typing/pasting
        }
    }

    @Override public void refreshFromController() {
        MemShellFormState s = controller.getState();
        applyCommonState(s);
        updating = true;
        boolean layoutVisibilityChanged = false;
        try {
            base64Mode.setSelected("base64".equalsIgnoreCase(s.getCustomInputMode()));
            fileMode.setSelected("file".equalsIgnoreCase(s.getCustomInputMode()));
            boolean nextBase64Visible = base64Mode.isSelected();
            boolean nextFileVisible = fileMode.isSelected();
            if (base64Panel.isVisible() != nextBase64Visible) {
                layoutVisibilityChanged = true;
            }
            if (filePanel.isVisible() != nextFileVisible) {
                layoutVisibilityChanged = true;
            }
            base64Panel.setVisible(nextBase64Visible);
            filePanel.setVisible(nextFileVisible);
            base64Area.setText(s.getShellClassBase64());
        } finally { updating = false; }
        if (layoutVisibilityChanged) {
            revalidate();
            repaint();
        }
    }
}
