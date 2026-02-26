package com.reajason.javaweb.desktop.memshell.ui;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.jupiter.api.Assertions.*;

class MemShellGeneratorFrameLayoutTest {

    @Test
    void shouldUseStackedLayoutWithoutSplitPaneAndKeepGenerateButton() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(), "Headless environment");

        final MemShellGeneratorFrame[] ref = new MemShellGeneratorFrame[1];
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                ref[0] = new MemShellGeneratorFrame();
            }
        });

        try {
            final JComponent[] contentRef = new JComponent[1];
            final JButton[] buttonRef = new JButton[1];
            final Dimension[] minSizeRef = new Dimension[1];
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    contentRef[0] = ref[0].getMainContentPanel();
                    buttonRef[0] = ref[0].getGenerateButton();
                    minSizeRef[0] = ref[0].getMinimumSize();
                }
            });

            assertNotNull(contentRef[0]);
            assertFalse(contentRef[0] instanceof JSplitPane, "main content should not be a JSplitPane");
            assertNotNull(buttonRef[0]);
            assertTrue(buttonRef[0].isEnabled());
            assertNotNull(minSizeRef[0]);
            assertTrue(minSizeRef[0].width >= 1180);
            assertTrue(minSizeRef[0].height >= 900);
        } finally {
            SwingUtilities.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    if (ref[0] != null) {
                        ref[0].dispose();
                    }
                }
            });
        }
    }
}
