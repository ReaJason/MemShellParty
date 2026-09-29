package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.PackerCategory;
import net.miginfocom.swing.MigLayout;

import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import java.awt.Component;
import java.awt.Dimension;
import java.util.List;

/**
 * ③ 打包配置条：分类 + 变体两个下拉。
 * 无子变体时变体禁用、packingMethod = 分文名；切换分类自动选中首个子变体。
 */
public class PackageConfigPanel extends JPanel {
    private final MemShellFormController controller;
    private final Runnable refreshAll;
    private boolean updating;

    private final JComboBox<PackerCategory> categoryCombo = new JComboBox<PackerCategory>();
    private final JComboBox<String> variantCombo = new JComboBox<String>();

    public PackageConfigPanel(MemShellFormController controller, Runnable refreshAll) {
        this.controller = controller;
        this.refreshAll = refreshAll;
        setLayout(new MigLayout("insets 4 8 4 8, fillx, gapx 8", "[][grow,fill][][grow,fill]", "[]"));

        add(new JLabel("打包分类"));
        add(categoryCombo, "growx");
        add(new JLabel("变体"));
        add(variantCombo, "growx");

        categoryCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof PackerCategory) {
                    setText(((PackerCategory) value).getName());
                }
                return this;
            }
        });

        lockComboWidths();

        categoryCombo.addActionListener(e -> {
            if (updating) return;
            Object item = categoryCombo.getSelectedItem();
            if (item instanceof PackerCategory) {
                PackerCategory category = (PackerCategory) item;
                String next = category.hasChildren() ? category.getChildren().get(0) : category.getName();
                controller.setPacker(next);
                refreshAll.run();
            }
        });

        variantCombo.addActionListener(e -> {
            if (updating) return;
            Object item = variantCombo.getSelectedItem();
            if (item != null && variantCombo.isEnabled()) {
                controller.setPacker(String.valueOf(item));
            }
        });
    }

    /**
     * JComboBox 首选宽度取当前 model 最宽项，切换分类/工具后 model 变化会导致两个输入框长度抖动。
     * 这里按全量目录的最长项锁定两个下拉的首选/最小宽度（过滤列表是全量的子集，宽度因此恒定）。
     * 变体框还需覆盖「无子变体时显示分类名」的情况，故分类名也参与变体宽度计算。
     */
    private void lockComboWidths() {
        DefaultComboBoxModel<PackerCategory> allCategories = new DefaultComboBoxModel<PackerCategory>();
        DefaultComboBoxModel<String> allVariants = new DefaultComboBoxModel<String>();
        for (PackerCategory category : controller.getCatalog().getPackers()) {
            allCategories.addElement(category);
            allVariants.addElement(category.getName());
            for (String child : category.getChildren()) {
                allVariants.addElement(child);
            }
        }
        fixComboWidth(categoryCombo, allCategories);
        fixComboWidth(variantCombo, allVariants);
    }

    private <T> void fixComboWidth(JComboBox<T> combo, ComboBoxModel<T> allItemsModel) {
        ComboBoxModel<T> original = combo.getModel();
        combo.setModel(allItemsModel);
        Dimension size = combo.getPreferredSize();
        combo.setModel(original);
        combo.setPreferredSize(size);
        combo.setMinimumSize(size);
    }

    public void refreshFromController() {
        updating = true;
        try {
            String selected = controller.getState().getPackingMethod();
            PackerCategory selectedCategory = controller.findCategoryOf(selected);

            DefaultComboBoxModel<PackerCategory> categoryModel = new DefaultComboBoxModel<PackerCategory>();
            List<PackerCategory> filtered = controller.getFilteredPackers();
            for (PackerCategory category : filtered) {
                categoryModel.addElement(category);
            }
            categoryCombo.setModel(categoryModel);
            if (selectedCategory != null) {
                categoryCombo.setSelectedItem(selectedCategory);
            } else if (categoryModel.getSize() > 0) {
                categoryCombo.setSelectedIndex(0);
            }

            rebuildVariants((PackerCategory) categoryCombo.getSelectedItem(), selected);
        } finally {
            updating = false;
        }
    }

    private void rebuildVariants(PackerCategory category, String selected) {
        DefaultComboBoxModel<String> variantModel = new DefaultComboBoxModel<String>();
        if (category != null && category.hasChildren()) {
            for (String child : category.getChildren()) {
                variantModel.addElement(child);
            }
        }
        variantCombo.setModel(variantModel);
        if (category != null && category.hasChildren()) {
            variantCombo.setEnabled(true);
            if (selected != null && category.getChildren().contains(selected)) {
                variantCombo.setSelectedItem(selected);
            } else if (variantModel.getSize() > 0) {
                variantCombo.setSelectedIndex(0);
            }
        } else {
            // 无子变体：变体禁用，packingMethod = 分文名
            variantCombo.setEnabled(false);
            variantCombo.setSelectedItem(category == null ? "" : category.getName());
        }
    }
}
