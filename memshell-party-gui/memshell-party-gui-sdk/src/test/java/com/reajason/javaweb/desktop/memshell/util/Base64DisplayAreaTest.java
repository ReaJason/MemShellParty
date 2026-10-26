package com.reajason.javaweb.desktop.memshell.util;

import org.junit.jupiter.api.Test;

import java.awt.Insets;
import java.awt.event.ComponentEvent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Base64 展示契约：换行是随组件宽度插入的显式 \n（文本区自身永不换行，
 * 字符级断行会触发 macOS 字形缓存污染），resize 时按新宽度重排，观感与原生
 * setLineWrap 一致；去掉展示换行必须还原原始串（复制/保存路径依赖这一点）；
 * 普通文本模式（源码/使用步骤）不受 resize 重排影响。
 */
class Base64DisplayAreaTest {

    @Test
    void wrapsAtFixedColumns() {
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            raw.append('A');
        }
        String display = Base64DisplayArea.wrapColumns(raw.toString(), 76);
        String[] lines = display.split("\n", -1);
        assertEquals(3, lines.length);
        assertEquals(76, lines[0].length());
        assertEquals(76, lines[1].length());
        assertEquals(48, lines[2].length());
        // 去掉展示换行还原原始串
        assertEquals(raw.toString(), display.replace("\n", ""));
    }

    @Test
    void leavesShortAndMultiLineContentAlone() {
        assertNull(Base64DisplayArea.wrapColumns(null, 76));
        String shortText = "yv66vgA=";
        assertSame(shortText, Base64DisplayArea.wrapColumns(shortText, 76));
        // 脚本类打包产物自带换行，不能再插展示换行把内容切碎
        StringBuilder script = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            script.append('x');
        }
        script.append('\n').append("second line");
        String scriptText = script.toString();
        assertSame(scriptText, Base64DisplayArea.wrapColumns(scriptText, 76));
    }

    @Test
    void rewrapsToFollowComponentWidth() {
        Base64DisplayArea area = new Base64DisplayArea();
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < 400; i++) {
            raw.append('A');
        }
        area.showBase64(raw.toString());
        // 布局前没有真实宽度：按默认列宽（MIME 76）展示，且文本区自身不换行
        assertEquals(Base64DisplayArea.DEFAULT_COLUMNS, area.getText().indexOf('\n'));
        assertFalse(area.getLineWrap());

        // 模拟布局给出真实宽度：期望列数 = (宽度 - insets - 1px 余量) / 小数字符宽
        double charWidth = area.getFontMetrics(area.getFont()).stringWidth("0000000000") / 10.0;
        Insets insets = area.getInsets();
        area.setSize((int) (charWidth * 50) + insets.left + insets.right + 2, 600);
        area.dispatchEvent(new ComponentEvent(area, ComponentEvent.COMPONENT_RESIZED));
        assertEquals(50, area.getText().indexOf('\n'));
        assertEquals(raw.toString(), area.getText().replace("\n", ""));

        // 变宽再重排
        area.setSize((int) (charWidth * 120) + insets.left + insets.right + 2, 600);
        area.dispatchEvent(new ComponentEvent(area, ComponentEvent.COMPONENT_RESIZED));
        assertEquals(120, area.getText().indexOf('\n'));
        assertEquals(raw.toString(), area.getText().replace("\n", ""));
    }

    @Test
    void preferredWidthStaysAnchoredRegardlessOfContent() {
        Base64DisplayArea area = new Base64DisplayArea();
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < 400; i++) {
            raw.append('A');
        }
        area.showBase64(raw.toString());
        // 重排到 120 列后内容行宽远超 40 列锚：首选宽度仍必须是列数锚，
        // 否则最小宽度被内容顶大、视口不再跟随缩放（窄窗口横滚条回归）
        double charWidth = area.getFontMetrics(area.getFont()).stringWidth("0000000000") / 10.0;
        Insets insets = area.getInsets();
        area.setSize((int) (charWidth * 120) + insets.left + insets.right + 2, 600);
        area.dispatchEvent(new ComponentEvent(area, ComponentEvent.COMPONENT_RESIZED));
        assertEquals(120, area.getText().indexOf('\n'));
        int anchor = area.getFontMetrics(area.getFont()).charWidth('m') * 40 + insets.left + insets.right;
        assertEquals(anchor, area.getPreferredSize().width);
        assertTrue(area.getPreferredSize().width < charWidth * 120);
    }

    @Test
    void plainTextModeIgnoresResize() {
        Base64DisplayArea area = new Base64DisplayArea();
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < 400; i++) {
            raw.append('A');
        }
        area.showBase64(raw.toString());
        area.showText("public class Foo {}", true);
        area.dispatchEvent(new ComponentEvent(area, ComponentEvent.COMPONENT_RESIZED));
        assertEquals("public class Foo {}", area.getText());
        assertTrue(area.getLineWrap());

        // 回到 Base64 模式：恢复宽度跟随
        area.showBase64(raw.toString());
        assertFalse(area.getLineWrap());
        assertEquals(raw.toString(), area.getText().replace("\n", ""));
    }
}
