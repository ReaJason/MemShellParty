package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

public abstract class AbstractToolPanel extends JPanel implements RefreshableToolPanel {
    protected final MemShellFormController controller;
    protected final Runnable refreshAll;
    protected boolean updating;

    protected final JComboBox<String> shellTypeCombo = new JComboBox<>();
    protected final JTextField urlPatternField = new JTextField();
    protected final JPanel shellTypeAndUrlRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[50%,fill][50%,fill]", "[]"));
    protected JPanel urlPatternRow = new JPanel(new BorderLayout());
    protected final JCheckBox randomClassNameCheck = new JCheckBox("随机类名");
    protected final JPanel manualClassPanel = new JPanel(new MigLayout("insets 0, fillx, gapx 8, gapy 2, wrap 2", "[grow,fill][grow,fill]", "[]"));
    protected final JTextField shellClassNameField = new JTextField();
    protected final JTextField injectorClassNameField = new JTextField();

    protected AbstractToolPanel(MemShellFormController controller, Runnable refreshAll) {
        this.controller = controller;
        this.refreshAll = refreshAll;
        setLayout(new MigLayout("insets 6, fillx, gapx 8, gapy 2, wrap 2", "[grow,fill][grow,fill]", "[]4[]"));
        buildCommonShellTypeSection();
    }

    protected void buildCommonShellTypeSection() {
        shellTypeAndUrlRow.add(labeled("内存马挂载类型", shellTypeCombo), "growx");
        urlPatternRow = labeled("请求路径", urlPatternField);
        shellTypeAndUrlRow.add(urlPatternRow, "growx");
        add(shellTypeAndUrlRow, "span 2, growx, wrap");

        shellTypeCombo.addActionListener(e -> {
            if (updating) return;
            Object item = shellTypeCombo.getSelectedItem();
            if (item != null) {
                controller.setShellType(String.valueOf(item));
                refreshAll.run();
            }
        });
        bindText(urlPatternField, controller::setUrlPattern);
    }

    protected void addRandomClassSection() {
        add(randomClassNameCheck, "span 2, split 2, wrap");
        manualClassPanel.add(labeled("内存马类名", shellClassNameField), "growx");
        manualClassPanel.add(labeled("注入器类名", injectorClassNameField), "growx");
        add(manualClassPanel, "span 2, growx, hidemode 3");

        randomClassNameCheck.addActionListener(e -> {
            if (updating) return;
            controller.setRandomClassName(randomClassNameCheck.isSelected());
            refreshAll.run();
        });
        bindText(shellClassNameField, controller::setShellClassName);
        bindText(injectorClassNameField, controller::setInjectorClassName);
    }

    protected JPanel labeled(String label, JComponent component) {
        JPanel p = new JPanel(new MigLayout("insets 0, fillx, wrap 1", "[grow,fill]", "[]1[]"));
        p.add(new JLabel(label), "growx");
        p.add(component, "growx");
        return p;
    }

    protected void setComboItems(JComboBox<String> combo, List<String> items, String selected) {
        combo.removeAllItems();
        for (String item : items) combo.addItem(item);
        if (selected != null) combo.setSelectedItem(selected);
    }

    protected void bindText(JTextField field, Consumer<String> setter) {
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                changed();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                changed();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                changed();
            }

            private void changed() {
                if (updating) return;
                setter.accept(field.getText());
            }
        });
    }

    protected void applyCommonState(MemShellFormState s) {
        updating = true;
        try {
            setComboItems(shellTypeCombo, controller.getShellTypesForCurrentTool(), s.getShellType());
            urlPatternField.setText(s.getUrlPattern());
            randomClassNameCheck.setSelected(s.isRandomClassName());
            boolean nextManualClassVisible = !s.isRandomClassName();
            manualClassPanel.setVisible(nextManualClassVisible);
            shellClassNameField.setText(s.getShellClassName());
            injectorClassNameField.setText(s.getInjectorClassName());
        } finally {
            updating = false;
        }
    }
}
