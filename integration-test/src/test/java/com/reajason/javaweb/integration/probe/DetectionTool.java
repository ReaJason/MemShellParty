package com.reajason.javaweb.integration.probe;

import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.probe.payload.BasicInfoPrinter;
import com.reajason.javaweb.probe.payload.JdkProbe;
import com.reajason.javaweb.probe.payload.ServerProbe;
import com.reajason.javaweb.probe.payload.filter.JettyFilterProbe;
import com.reajason.javaweb.probe.payload.filter.ResinFilterProbe;
import com.reajason.javaweb.probe.payload.filter.TomcatFilterProbe;
import com.reajason.javaweb.probe.payload.filter.UndertowFilterProbe;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2025/7/28
 */
public class DetectionTool {

    public static String getBase64Class(Class<?> clazz) {
        return Base64.encodeBase64String(new ByteBuddy()
                .redefine(clazz)
                .name(CommonUtil.generateShellClassName())
                .visit(TargetJreVersionVisitorWrapper.DEFAULT)
                .make().getBytes());
    }

    public static String getJdkDetection() {
        return getBase64Class(JdkProbe.class);
    }

    public static String getBasicInfoPrinter() {
        return getBase64Class(BasicInfoPrinter.class);
    }

    public static String getServerDetection() {
        return getBase64Class(ServerProbe.class);
    }

    public static String getTomcatFilterProbe() {
        return getBase64Class(TomcatFilterProbe.class);
    }

    public static String getJettyFilterProbe() {
        return getBase64Class(JettyFilterProbe.class);
    }

    public static String getResinFilterProbe() {
        return getBase64Class(ResinFilterProbe.class);
    }

    public static String getUndertowFilterProbe() {
        return getBase64Class(UndertowFilterProbe.class);
    }
}
