package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.ResultPanel;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.jupiter.api.Assertions.*;

class ResultPanelBasicInfoLayoutTest {

    @Test
    void shouldUseStructuredNoScrollBasicInfo() throws Exception {
        MemShellFormController controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        controller.setServer("Tomcat");
        controller.setShellTool("Godzilla");
        controller.setShellType("Listener");
        controller.setPacker("Base64");
        DesktopMemShellGenerateResult result = new GenerationService().generate(controller.getState().copy());

        final ResultPanel panel = new ResultPanel();
        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {
                panel.showResult(result);
            }
        });

        JComponent basic = panel.getBasicInfoComponent();
        assertNotNull(basic);
        assertTrue(basic instanceof JPanel);
        assertFalse(containsScrollPane(basic), "basic info section should not contain JScrollPane");
        assertTrue(containsText(panel, "服务类型"));
        assertTrue(containsText(panel, "内存马功能"));
        assertTrue(containsText(panel, "注入器类名"));
        assertTrue(containsText(panel, "内存马类名"));
    }

    private boolean containsScrollPane(Component c) {
        if (c instanceof JScrollPane) return true;
        if (c instanceof Container) {
            for (Component child : ((Container) c).getComponents()) {
                if (containsScrollPane(child)) return true;
            }
        }
        return false;
    }

    private boolean containsText(Component c, String expected) {
        if (c instanceof JLabel) {
            String text = ((JLabel) c).getText();
            if (text != null && text.contains(expected)) return true;
        }
        if (c instanceof JTextField) {
            String text = ((JTextField) c).getText();
            if (text != null && text.contains(expected)) return true;
        }
        if (c instanceof Container) {
            for (Component child : ((Container) c).getComponents()) {
                if (containsText(child, expected)) return true;
            }
        }
        return false;
    }
}
