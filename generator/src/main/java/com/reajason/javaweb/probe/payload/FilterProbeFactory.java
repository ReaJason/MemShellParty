package com.reajason.javaweb.probe.payload;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.probe.payload.filter.*;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2026/1/11
 */
public class FilterProbeFactory {

    public static String getBase64ByServer(String server) {
        try (DynamicType.Unloaded<?> unloaded = new ByteBuddy()
                .redefine(getFilterClass(server))
                .visit(TargetJreVersionVisitorWrapper.DEFAULT)
                .name(CommonUtil.generateClassName()).make()) {
            return Base64.encodeBase64String(unloaded.getBytes());
        }
    }


    private static Class<?> getFilterClass(String server) {
        switch (server) {
            case Server.Tomcat:
            case Server.JBoss:
            case Server.BES:
            case Server.TongWeb:
                return TomcatFilterProbe.class;
            case Server.Jetty:
                return JettyFilterProbe.class;
            case Server.Apusic:
                return ApusicFilterProbe.class;
            case Server.GlassFish:
            case Server.InforSuite:
                return GlassFishFilterProbe.class;
            case Server.WebSphere:
                return WebSphereFilterProbe.class;
            case Server.WebLogic:
                return WebLogicFilterProbe.class;
            case Server.Undertow:
                return UndertowFilterProbe.class;
            case Server.Resin:
                return ResinFilterProbe.class;
            default:
                throw new GenerationException("filterProbe not supported for server: " + server);
        }
    }
}
