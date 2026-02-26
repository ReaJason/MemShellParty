package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.PackerEntryModel;
import com.reajason.javaweb.desktop.memshell.model.PackerSchemaFieldModel;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PackageConfigPanel extends JPanel {
    private final MemShellFormController controller;
    private final Runnable refreshAll;
    private boolean updating;

    private final JComboBox<PackerEntryModel> packerCombo = new JComboBox<>();
    private final JPanel dynamicFieldsPanel = new JPanel(new MigLayout("insets 0, fillx, gapx 8, gapy 2, wrap 2", "[grow,fill][grow,fill]", "[]"));

    public PackageConfigPanel(MemShellFormController controller, Runnable refreshAll) {
        super(new MigLayout("insets 8, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        this.controller = controller;
        this.refreshAll = refreshAll;
        setBorder(BorderFactory.createTitledBorder("打包配置"));

        JPanel top = new JPanel(new MigLayout("insets 0, fillx, wrap 1", "[grow,fill]", "[]1[]"));
        top.add(new JLabel("打包方式"));
        top.add(packerCombo, "growx");
        add(top, "growx");
        add(dynamicFieldsPanel, "growx");

        packerCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public java.awt.Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof PackerEntryModel) {
                    PackerEntryModel p = (PackerEntryModel) value;
                    setText(p.displayLabel());
                }
                return this;
            }
        });

        packerCombo.addActionListener(e -> {
            if (updating) return;
            Object item = packerCombo.getSelectedItem();
            if (item instanceof PackerEntryModel) {
                PackerEntryModel p = (PackerEntryModel) item;
                controller.setPacker(p.getName());
                refreshAll.run();
            }
        });
    }

    public void refreshFromController() {
        updating = true;
        try {
            DefaultComboBoxModel<PackerEntryModel> model = new DefaultComboBoxModel<>();
            List<PackerEntryModel> filtered = controller.getFilteredPackers();
            PackerEntryModel selected = controller.getSelectedPackerEntry();
            for (PackerEntryModel p : filtered) model.addElement(p);
            packerCombo.setModel(model);
            if (selected != null) packerCombo.setSelectedItem(selected);
            rebuildDynamicFields(controller.getSelectedPackerFields(), controller.getPackerCustomConfig());
        } finally {
            updating = false;
        }
    }

    private void rebuildDynamicFields(List<PackerSchemaFieldModel> fields, Map<String, Object> currentValues) {
        dynamicFieldsPanel.removeAll();
        if (fields == null || fields.isEmpty()) {
            dynamicFieldsPanel.revalidate();
            dynamicFieldsPanel.repaint();
            return;
        }
        for (PackerSchemaFieldModel field : fields) {
            String type = field.getType();
            if (!"BOOLEAN".equals(type) && !"STRING".equals(type) && !"ENUM".equals(type) && !"INTEGER".equals(type)) {
                continue;
            }
            Object value = currentValues.get(field.getKey());
            if ("BOOLEAN".equals(type)) {
                JCheckBox check = new JCheckBox(field.getKey());
                check.setSelected(Boolean.TRUE.equals(value));
                check.addActionListener(e -> controller.setPackerCustomField(field.getKey(), check.isSelected()));
                dynamicFieldsPanel.add(check, "span 2, growx");
                continue;
            }
            dynamicFieldsPanel.add(new JLabel(field.getKey()));
            if ("ENUM".equals(type)) {
                JComboBox<String> combo = new JComboBox<>();
                for (PackerSchemaFieldModel.Option option : field.getOptions()) {
                    combo.addItem(option.getValue());
                }
                if (value != null) combo.setSelectedItem(String.valueOf(value));
                combo.addActionListener(e -> controller.setPackerCustomField(field.getKey(), combo.getSelectedItem()));
                dynamicFieldsPanel.add(combo, "growx");
            } else {
                JTextField text = new JTextField(value == null ? "" : String.valueOf(value));
                text.getDocument().addDocumentListener(new DocumentListener() {
                    @Override public void insertUpdate(DocumentEvent e) { changed(); }
                    @Override public void removeUpdate(DocumentEvent e) { changed(); }
                    @Override public void changedUpdate(DocumentEvent e) { changed(); }
                    private void changed() {
                        if (updating) return;
                        if ("INTEGER".equals(type)) {
                            String raw = text.getText().trim();
                            if (raw.isEmpty()) {
                                controller.setPackerCustomField(field.getKey(), null);
                            } else {
                                try {
                                    controller.setPackerCustomField(field.getKey(), Integer.parseInt(raw));
                                } catch (NumberFormatException ignored) {
                                }
                            }
                        } else {
                            controller.setPackerCustomField(field.getKey(), text.getText());
                        }
                    }
                });
                dynamicFieldsPanel.add(text, "growx");
            }
        }
        dynamicFieldsPanel.revalidate();
        dynamicFieldsPanel.repaint();
    }
}
