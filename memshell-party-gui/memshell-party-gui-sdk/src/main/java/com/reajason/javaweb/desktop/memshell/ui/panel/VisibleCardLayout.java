package com.reajason.javaweb.desktop.memshell.ui.panel;

import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Insets;

/**
 * 只按当前可见卡片计算首选高度的 CardLayout。
 * 原生 CardLayout 的 preferredSize 取所有卡片最大值，最高的卡片会撑出大片空白；
 * 改为可见卡片驱动后，容器高度随卡片切换收紧（内存马功能区、探测马条件行共用）。
 */
public class VisibleCardLayout extends CardLayout {
    private Component current;

    @Override
    public void show(Container parent, String name) {
        super.show(parent, name);
        for (Component c : parent.getComponents()) {
            if (c.isVisible()) {
                current = c;
                break;
            }
        }
    }

    @Override
    public Dimension preferredLayoutSize(Container parent) {
        if (current == null) {
            return super.preferredLayoutSize(parent);
        }
        Insets insets = parent.getInsets();
        Dimension d = current.getPreferredSize();
        return new Dimension(d.width + insets.left + insets.right, d.height + insets.top + insets.bottom);
    }

    @Override
    public Dimension minimumLayoutSize(Container parent) {
        return preferredLayoutSize(parent);
    }
}
