package com.reajason.javaweb.desktop.memshell;

import com.formdev.flatlaf.FlatLightLaf;
import com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame;

import javax.swing.*;

public class MemShellDesktopApplication {
    public static void main(String[] args) {
        FlatLightLaf.setup();
        SwingUtilities.invokeLater(() -> new MemShellGeneratorFrame().setVisible(true));
    }
}
