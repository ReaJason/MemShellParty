package com.reajason.javaweb.memshell.config;

import net.bytebuddy.jar.asm.Opcodes;

/**
 * @author ReaJason
 * @since 2024/11/28
 */
public class Constants {
    public static final int DEFAULT_VERSION = Opcodes.V1_6;

    public static final String SERVLET = "Servlet";
    public static final String JAKARTA_SERVLET = "JakartaServlet";
    public static final String FILTER = "Filter";
    public static final String JAKARTA_FILTER = "JakartaFilter";
    public static final String LISTENER = "Listener";
    public static final String JAKARTA_LISTENER = "JakartaListener";

    public static final String VALVE = "Valve";
    public static final String JAKARTA_VALVE = "JakartaValve";

    public static final String AGENT = "Agent";
}
