package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.memshell.obfuscation.OptionRegistry;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Insets;
import java.awt.Window;
import java.util.List;
import java.util.Map;

/**
 * 混淆参数参考弹窗：列出 {@link OptionRegistry} 注册的全部参数（名称/类型/默认值/说明），
 * 与 web 端「参数参考」弹窗、MCP memshell_capabilities 的 obfuscationOptions 同源。
 * class-obf 上游还有注册表之外的配置（badAnno 文件类、junk 等），因安全/基线原因刻意不暴露，
 * 用户以本表为准。
 */
public final class ObfuscationOptionsDialog extends JDialog {

    private static final String[] COLUMNS = {"参数", "类型", "默认值", "说明"};

    public ObfuscationOptionsDialog(Window owner) {
        super(owner, "混淆参数参考", ModalityType.MODELESS);
        // 数据全部来自静态注册表，每次打开重建即可，关掉直接释放
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

        // 提示文案保持纯 CJK/全角：拉丁段在此弹窗的混排会污染 macOS 字形缓存（实测 key=value
        // 丢等号字形），规则见 ResultPanel 空态提示注释
        JLabel hint = new JLabel("下表为全部可填参数及默认值，每行按「键＝值」覆盖一项");
        hint.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));

        JTable table = new JTable(buildModel());
        table.setFillsViewportHeight(true);
        table.setRowHeight(table.getRowHeight() + 4);
        table.getColumnModel().getColumn(0).setPreferredWidth(170);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(2).setPreferredWidth(130);
        table.getColumnModel().getColumn(3).setPreferredWidth(400);
        // 参数名与默认值是代码标识符，等宽字体便于对照输入框里的 key
        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, table.getFont().getSize());
        DefaultTableCellRenderer monoRenderer = new DefaultTableCellRenderer();
        monoRenderer.setFont(mono);
        table.getColumnModel().getColumn(0).setCellRenderer(monoRenderer);
        table.getColumnModel().getColumn(2).setCellRenderer(monoRenderer);

        setLayout(new MigLayout("insets 8, fill, wrap 1, gapy 6", "[grow,fill]", "[][grow,fill]"));
        add(hint, "growx");
        add(new JScrollPane(table), "grow, push");

        setSize(new Dimension(860, 520));
        setLocationRelativeTo(owner);
    }

    /**
     * 「混淆参数」标签旁的 "?" 按钮：点击弹出参数参考。不参与焦点遍历，避免打断参数输入。
     */
    public static JButton createHelpButton() {
        JButton button = new JButton("?");
        button.setMargin(new Insets(1, 5, 1, 5));
        button.setFont(button.getFont().deriveFont(Font.PLAIN, button.getFont().getSize() - 1f));
        button.setFocusable(false);
        button.setToolTipText("查看支持的全部混淆参数与默认值");
        button.addActionListener(e -> showReference(button));
        return button;
    }

    public static void showReference(Component anchor) {
        Window owner = anchor == null ? null : SwingUtilities.getWindowAncestor(anchor);
        new ObfuscationOptionsDialog(owner).setVisible(true);
    }

    private static DefaultTableModel buildModel() {
        DefaultTableModel model = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        for (Map<String, Object> option : OptionRegistry.describeAll()) {
            model.addRow(new Object[]{
                    option.get("name"),
                    formatType(option),
                    formatDefault(option.get("defaultValue")),
                    option.get("description"),
            });
        }
        return model;
    }

    private static String formatType(Map<String, Object> option) {
        String type = String.valueOf(option.get("type"));
        Object min = option.get("min");
        Object max = option.get("max");
        if ("integer".equals(type) && min != null && max != null) {
            return type + " (" + min + "-" + max + ")";
        }
        return type;
    }

    /**
     * 默认值展示：null 表示运行时随机生成（如 aesKey），空列表显示「（空）」。
     */
    private static String formatDefault(Object value) {
        if (value == null) {
            return "自动生成";
        }
        if (value instanceof List) {
            List<?> list = (List<?>) value;
            if (list.isEmpty()) {
                return "（空）";
            }
            StringBuilder sb = new StringBuilder();
            for (Object item : list) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(item);
            }
            return sb.toString();
        }
        return String.valueOf(value);
    }
}
