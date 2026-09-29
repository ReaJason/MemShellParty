package com.reajason.javaweb.desktop.memshell.util;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

/**
 * 剪贴板工具。
 */
public final class ClipboardUtil {

    private ClipboardUtil() {
    }

    public static void copyText(String text) {
        if (text == null) {
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }
}
