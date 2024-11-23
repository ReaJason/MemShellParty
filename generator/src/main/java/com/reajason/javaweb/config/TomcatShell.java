package com.reajason.javaweb.config;

import com.reajason.javaweb.memsell.tomcat.godzilla.GodzillaFilter;
import lombok.Getter;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public class TomcatShell {
    public static final String SERVLET = "servlet";
    public static final String JAKARTA_SERVLET = "jakartaServlet";
    public static final String FILTER = "filter";
    public static final String JAKARTA_FILTER = "jakartaFilter";
    public static final String LISTENER = "listener";
    public static final String JAKARTA_LISTENER = "jakartaListener";
    public static final String WEBSOCKET = "websocket";
    public static final String VALVE = "valve";
    public static final String UPGRADE = "upgrade";
    public static final String EXECUTOR = "executor";


    @Getter
    public static enum Godzilla {

        /**
         * Tomcat Filter
         */
        Filter(TomcatShell.FILTER, GodzillaFilter.class),
        ;

        Godzilla(String shellType, Class<?> shellClass) {
            this.shellClass = shellClass;
            this.shellType = shellType;
        }

        private final String shellType;
        private final Class<?> shellClass;

    }
}
