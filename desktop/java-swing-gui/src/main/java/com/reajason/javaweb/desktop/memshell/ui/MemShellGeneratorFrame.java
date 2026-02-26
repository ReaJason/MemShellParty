package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.MainConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.PackageConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.ResultPanel;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;

public class MemShellGeneratorFrame extends JFrame {
    private final MemShellFormController controller;
    private final GenerationService generationService;
    private final MainConfigPanel mainConfigPanel;
    private final PackageConfigPanel packageConfigPanel;
    private final ResultPanel resultPanel;
    private final JButton generateButton = new JButton("生成内存马");
    private final JLabel statusLabel = new JLabel("就绪");
    private JComponent mainContentPanel;

    public MemShellGeneratorFrame() {
        super("MemShellParty - MemShellGenerator");
        this.controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        this.generationService = new GenerationService();
        CustomClassNameParser customClassNameParser = new CustomClassNameParser();

        this.resultPanel = new ResultPanel();
        this.mainConfigPanel = new MainConfigPanel(controller, customClassNameParser, this::refreshAll);
        this.packageConfigPanel = new PackageConfigPanel(controller, this::refreshAll);

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1180, 900));
        setSize(1280, 900);
        setLocationRelativeTo(null);

        setLayout(new BorderLayout(6, 6));
        add(buildToolbar(), BorderLayout.NORTH);
        add(buildContent(), BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);

        generateButton.addActionListener(e -> onGenerate());
        resultPanel.clear();
        refreshAll();
    }

    private JComponent buildToolbar() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createEmptyBorder(4, 8, 2, 8));
        return p;
    }

    private JComponent buildContent() {
        JPanel topPane = new JPanel(new MigLayout("insets 0, fillx, wrap 1", "[grow,fill]", "[][]"));
        JPanel leftColumn = new JPanel(new MigLayout("insets 0, fillx, wrap 1", "[grow,fill]", "[]6[]"));
        leftColumn.add(mainConfigPanel.getCorePanelComponent(), "growx");
        leftColumn.add(packageConfigPanel, "growx");

        JPanel rightColumn = new JPanel(new MigLayout("insets 0, fillx, wrap 1", "[grow,fill]", "[]"));
        rightColumn.add(mainConfigPanel.getToolPanelComponent(), "growx");

        JPanel topColumns = new JPanel(new MigLayout("insets 0, fillx, aligny top, gapx 8, wrap 2",
                "[grow,fill,sg topCol][grow,fill,sg topCol]",
                "[top]"));
        topColumns.add(leftColumn, "growx, pushx, top");
        topColumns.add(rightColumn, "growx, pushx, top");
        topPane.add(topColumns, "growx, pushy");

        topPane.add(generateButton, "wrap, growx, gaptop 10");
        generateButton.setFont(generateButton.getFont().deriveFont(Font.BOLD, 14f));

        JPanel content = new JPanel(new MigLayout("insets 0, fill, wrap 1", "[grow,fill]", "[][grow,fill]"));
        content.add(topPane, "growx");
        content.add(resultPanel, "grow, push");
        mainContentPanel = content;
        return content;
    }

    private JComponent buildStatusBar() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        p.add(statusLabel, BorderLayout.WEST);
        return p;
    }

    private void onGenerate() {
        com.reajason.javaweb.desktop.memshell.validation.MemShellValidator.Result validation = controller.validate();
        if (!validation.isValid()) {
            statusLabel.setText("校验失败");
            SwingUiUtil.showError(this, validation.firstMessage());
            return;
        }
        generateButton.setEnabled(false);
        statusLabel.setText("生成中...");

        SwingWorker<DesktopMemShellGenerateResult, Void> worker = new SwingWorker<DesktopMemShellGenerateResult, Void>() {
            @Override
            protected DesktopMemShellGenerateResult doInBackground() {
                return generationService.generate(controller.getState().copy());
            }

            @Override
            protected void done() {
                generateButton.setEnabled(true);
                try {
                    DesktopMemShellGenerateResult result = get();
                    resultPanel.showResult(result);
                    statusLabel.setText("生成成功");
                } catch (Exception ex) {
                    statusLabel.setText("生成失败");
                    SwingUiUtil.showError(MemShellGeneratorFrame.this, "生成失败: " + (ex.getCause() != null ? ex.getCause().getMessage() : ex.getMessage()));
                }
            }
        };
        worker.execute();
    }

    public void refreshAll() {
        mainConfigPanel.refreshFromController();
        packageConfigPanel.refreshFromController();
        repaint();
        revalidate();
    }

    JComponent getMainContentPanel() {
        return mainContentPanel;
    }

    JButton getGenerateButton() {
        return generateButton;
    }
}
