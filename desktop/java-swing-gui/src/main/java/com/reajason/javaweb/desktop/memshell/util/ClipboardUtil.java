package com.reajason.javaweb.desktop.memshell.util;

import java.awt.*;
import java.awt.datatransfer.StringSelection;

public final class ClipboardUtil {
    private ClipboardUtil() {}

    public static void copyText(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text == null ? "" : text), null);
    }
}
