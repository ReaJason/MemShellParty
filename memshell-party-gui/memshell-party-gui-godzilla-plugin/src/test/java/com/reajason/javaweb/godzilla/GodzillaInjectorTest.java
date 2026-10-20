package com.reajason.javaweb.godzilla;

import com.reajason.javaweb.desktop.memshell.model.InfoRow;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ResultInfoService;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import core.imp.Payload;
import core.shell.ShellEntity;
import javassist.ClassPool;
import javassist.CtClass;
import org.junit.jupiter.api.Test;
import util.http.ReqParameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 按参考插件的协议跑通「生成 → include 装载器 → eval 触发注入」：
 * FakePayload 在本地模拟 JavaDynamicPayload 的 include/evalFunc 语义（含 Javassist 重命名），
 * 不需要真实中间件即可验证参数编码、类装载与回传。
 */
class GodzillaInjectorTest {

    @Test
    void generatesAndInjectsTomcatFilterShell() throws Exception {
        MemShellFormState state = state("Tomcat", "Godzilla", "Filter", "/*");

        MemShellResult result = GodzillaInjector.generate(state);

        assertNotNull(result.getInjectorBytes());
        assertNotNull(result.getInjectorClassName());
        assertEquals((byte) 0xCA, result.getInjectorBytes()[0]);
        assertEquals((byte) 0xFE, result.getInjectorBytes()[1]);
        assertEquals((byte) 0xBA, result.getInjectorBytes()[2]);
        assertEquals((byte) 0xBE, result.getInjectorBytes()[3]);
        assertTrue(result.getShellClassName().length() > 0);
        assertTrue(result.getShellBytes().length > 0);

        FakePayload payload = new FakePayload();
        String output = GodzillaInjector.inject(payload, null, result);

        assertNotNull(output);
        assertFalse(output.startsWith(B64Runner.ERROR_PREFIX), output);
        assertTrue(payload.included.containsKey(GodzillaInjector.RUNNER_CLASS_NAME));
        assertTrue(output.contains("context"), "注入器应回传上下文探测信息，实际：" + output);

        GodzillaConfig config = (GodzillaConfig) result.getShellToolConfig();
        assertFalse(config.getPass().trim().isEmpty());
        assertFalse(config.getKey().trim().isEmpty());
        assertEquals("User-Agent", config.getHeaderName());

        List<InfoRow> rows = ResultInfoService.describeTool(result.getShellConfig(), result.getShellToolConfig());
        assertFalse(rows.isEmpty());
        boolean hasPassword = false;
        for (InfoRow row : rows) {
            if (row.getValue().equals(config.getPass())) {
                hasPassword = true;
            }
        }
        assertTrue(hasPassword, "连接信息里应包含生成的密码");
    }

    @Test
    void requestCarriesInjectorAndInnerClassBytes() throws Exception {
        MemShellFormState state = state("Tomcat", "Godzilla", "Listener", "/*");
        MemShellResult result = GodzillaInjector.generate(state);

        FakePayload payload = new FakePayload();
        GodzillaInjector.inject(payload, null, result);

        ReqParameter parameter = payload.lastParameter;
        assertNotNull(parameter);
        assertNotNull(parameter.get("p1"));
        assertEquals(result.getInjectorClassName(), new String(parameter.get("p3"), "UTF-8"));
        assertTrue(parameter.get("p2").length > 0);
    }

    /**
     * Agent 模板带匿名内部类（界面会过滤掉 Agent 类型，但装载协议本身必须支持）：
     * 内部类先定义、主类后定义，二者在同一个装载器里才能互相解析。
     */
    @Test
    void deliversInnerClassesForAgentTemplates() throws Exception {
        MemShellFormState state = state("Apusic", "Godzilla", "AgentFilterChain", "/*");
        MemShellResult result = GodzillaInjector.generate(state);

        assertNotNull(result.getInjectorInnerClassBytes());
        assertFalse(result.getInjectorInnerClassBytes().isEmpty(), "Agent 模板应带内部类");

        FakePayload payload = new FakePayload();
        String output = GodzillaInjector.inject(payload, null, result);
        assertFalse(output.startsWith(B64Runner.ERROR_PREFIX), output);
    }

    private static MemShellFormState state(String server, String tool, String type, String urlPattern) {
        MemShellFormState state = new MemShellFormState();
        state.setServer(server);
        state.setServerVersion("Unknown");
        state.setShellTool(tool);
        state.setShellType(type);
        state.setUrlPattern(urlPattern);
        state.setShrink(true);
        state.setStaticInitialize(true);
        return state;
    }

    /**
     * 只实现插件真正用到的 include/evalFunc，其余方法给默认值。
     */
    private static final class FakePayload implements Payload {
        private final Map<String, byte[]> included = new HashMap<String, byte[]>();
        private ReqParameter lastParameter;

        @Override
        public boolean include(String codeName, byte[] binCode) {
            included.put(codeName, binCode);
            return true;
        }

        @Override
        public byte[] evalFunc(String className, String funcName, ReqParameter parameter) {
            lastParameter = parameter;
            if (!included.containsKey(className)) {
                return "evalClass is null".getBytes();
            }
            try {
                // 模拟 Godzilla 的 dynamicUpdateClassName + include：Javassist 改成一个混淆类名再 define
                String renamed = "org.apache.coyote.BeanDescription";
                byte[] renamedBytes = rename(included.get(className), renamed);
                Class<?> runnerClass = new SingleClassLoader(Thread.currentThread().getContextClassLoader())
                        .define(renamed, renamedBytes);
                Object runner = runnerClass.newInstance();
                Map<String, Object> map = new HashMap<String, Object>();
                copy(parameter, map, "p1");
                copy(parameter, map, "p2");
                copy(parameter, map, "p3");
                runnerClass.getMethod("equals", Object.class).invoke(runner, map);
                Object result = map.get("result");
                return result instanceof byte[] ? (byte[]) result : new byte[0];
            } catch (Throwable t) {
                return (B64Runner.ERROR_PREFIX + t).getBytes();
            }
        }

        private static void copy(ReqParameter parameter, Map<String, Object> map, String key) {
            byte[] value = parameter.get(key);
            if (value != null) {
                map.put(key, value);
            }
        }

        private static byte[] rename(byte[] bytes, String newName) throws Exception {
            ClassPool pool = new ClassPool(true);
            CtClass ctClass = pool.makeClass(new ByteArrayInputStream(bytes));
            ctClass.setName(newName);
            byte[] renamed = ctClass.toBytecode();
            ctClass.detach();
            return renamed;
        }

        @Override
        public void init(ShellEntity shellEntity) {
        }

        @Override
        public byte[] getPayload() {
            return new byte[0];
        }

        @Override
        public String getFile(String fileName) {
            return null;
        }

        @Override
        public String[] listFileRoot() {
            return new String[0];
        }

        @Override
        public byte[] downloadFile(String fileName) {
            return new byte[0];
        }

        @Override
        public String getOsInfo() {
            return "";
        }

        @Override
        public String getBasicsInfo() {
            return "";
        }

        @Override
        public void fillParameter(String className, String funcName, ReqParameter parameter) {
        }

        @Override
        public String execCommand(String commandStr) {
            return "";
        }

        @Override
        public boolean uploadFile(String fileName, byte[] data) {
            return false;
        }

        @Override
        public boolean copyFile(String fileName, String newFile) {
            return false;
        }

        @Override
        public boolean deleteFile(String fileName) {
            return false;
        }

        @Override
        public boolean moveFile(String fileName, String newFile) {
            return false;
        }

        @Override
        public boolean newFile(String fileName) {
            return false;
        }

        @Override
        public boolean newDir(String fileName) {
            return false;
        }

        @Override
        public boolean test() {
            return false;
        }

        @Override
        public boolean fileRemoteDown(String url, String saveFile) {
            return false;
        }

        @Override
        public boolean setFileAttr(String fileName, String fileType, String fileAttr) {
            return false;
        }

        @Override
        public boolean close() {
            return false;
        }

        @Override
        @SuppressWarnings("rawtypes")
        public String execSql(String execSql, String dbType, int connTimeOut, String databaseName,
                              String username, String dbPassword, Map dbInfo, String charset) {
            return "";
        }

        @Override
        public String[] getAllDatabaseType() {
            return new String[0];
        }

        @Override
        public String currentDir() {
            return "";
        }

        @Override
        public String currentUserName() {
            return "";
        }

        @Override
        public String bigFileUpload(String fileName, int index, byte[] data) {
            return "";
        }

        @Override
        public String getTempDirectory() {
            return "";
        }

        @Override
        public byte[] bigFileDownload(String fileName, int index, int size) {
            return new byte[0];
        }

        @Override
        public int getFileSize(String fileName) {
            return 0;
        }

        @Override
        public boolean isWindows() {
            return false;
        }

        @Override
        public boolean isAlive() {
            return true;
        }

        @Override
        public boolean isX64() {
            return true;
        }
    }

    private static final class SingleClassLoader extends ClassLoader {
        private SingleClassLoader(ClassLoader parent) {
            super(parent);
        }

        private Class<?> define(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length);
        }
    }
}
