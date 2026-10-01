package com.reajason.javaweb.desktop.memshell.util;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

/**
 * 剪贴板工具。
 */
public final class ClipboardUtil {

    private ClipboardUtil() {
    }

    /**
     * 尝试复制文本；系统剪贴板被其他进程占用或当前环境不允许访问时返回 false。
     */
    public static boolean copyText(String text) {
        if (text == null) {
            return false;
        }
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
            return true;
        } catch (IllegalStateException | SecurityException | java.awt.HeadlessException ex) {
            return false;
        }
    }
}
