/*
 * Copyright 2014 - Present Rafael Winterhalter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.CodeSource;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * Copy from <a href="https://github.com/raphw/byte-buddy/blob/master/byte-buddy-agent">Byte Buddy</a>
 */
public class Attacher {

    /**
     * Representation of the bootstrap {@link java.lang.ClassLoader}.
     */
    private static final ClassLoader BOOTSTRAP_CLASS_LOADER = null;

    /**
     * The character that is used to mark the beginning of the argument to the agent.
     */
    private static final String AGENT_ARGUMENT_SEPARATOR = "=";

    /**
     * The agent provides only {@code static} utility methods and should not be instantiated.
     */
    private Attacher() {
        throw new UnsupportedOperationException("This class is a utility class and not supposed to be instantiated");
    }

    /**
     * <p>
     * Attaches the given agent Jar on the target process which must be a virtual machine process. The default attachment provider
     * is used for applying the attachment. This operation blocks until the attachment is complete. If the current VM does not supply
     * any known form of attachment to a remote VM, an {@link IllegalStateException} is thrown. The agent is not provided an argument.
     * </p>
     * <p>
     * <b>Important</b>: It is only possible to attach to processes that are executed by the same operating system user.
     * </p>
     *
     * @param agentJar  The agent jar file.
     * @param processId The target process id.
     */
    public static void attach(File agentJar, String processId) {
        attach(agentJar, processId, null);
    }

    public static void attach(String processId) {
        attach(trySelfResolve(), processId, null);
    }

    /**
     * <p>
     * Attaches the given agent Jar on the target process which must be a virtual machine process. The default attachment provider
     * is used for applying the attachment. This operation blocks until the attachment is complete. If the current VM does not supply
     * any known form of attachment to a remote VM, an {@link IllegalStateException} is thrown.
     * </p>
     * <p>
     * <b>Important</b>: It is only possible to attach to processes that are executed by the same operating system user.
     * </p>
     *
     * @param agentJar  The agent jar file.
     * @param processId The target process id.
     * @param argument  The argument to provide to the agent.
     */
    public static void attach(File agentJar, String processId, String argument) {
        install(processId, argument, new AgentProvider.ForExistingAgent(agentJar));
    }

    /**
     * <p>
     * Lists all discoverable Java processes on the local host.
     * Supports both HotSpot and OpenJ9 JVMs across Windows, macOS, and Linux.
     * </p>
     * <p>
     * HotSpot processes are discovered by scanning {@code hsperfdata_<user>} directories
     * in the system temporary folder and parsing PerfData binary files to extract
     * the main class name. OpenJ9 processes are discovered by scanning
     * {@code .com_ibm_tools_attach} directories and reading {@code attachInfo} property files.
     * </p>
     * <p>
     * <b>Note</b>: Only processes accessible to the current user are listed.
     * Stale entries from crashed JVMs may appear. Processes started with
     * {@code -XX:-UsePerfData} will not be discoverable via HotSpot scanning.
     * </p>
     *
     * @return A list of discovered Java process descriptors.
     */
    public static List<JavaProcessDescriptor> listJavaProcesses() {
        List<JavaProcessDescriptor> processes = new ArrayList<JavaProcessDescriptor>();
        Set<String> seenPids = new HashSet<String>();
        for (JavaProcessDescriptor descriptor : HotSpotProcessDiscovery.discover()) {
            if (seenPids.add(descriptor.getPid())) {
                processes.add(descriptor);
            }
        }
        for (JavaProcessDescriptor descriptor : OpenJ9ProcessDiscovery.discover()) {
            if (seenPids.add(descriptor.getPid())) {
                processes.add(descriptor);
            }
        }
        return processes;
    }

    /**
     * Installs a Java agent on a target VM.
     *
     * @param processId     The process id of the target JVM process.
     * @param argument      The argument to provide to the agent.
     * @param agentProvider The agent provider for the agent jar or library.
     */
    private static void install(String processId, String argument, AgentProvider agentProvider) {
        AttachmentProvider.Accessor attachmentAccessor = AttachmentProvider.DEFAULT.attempt();
        if (!attachmentAccessor.isAvailable()) {
            throw new IllegalStateException("No compatible attachment provider is available");
        }
        try {
            Class<?> virtualMachineType = attachmentAccessor.getVirtualMachineType();
            String agent = agentProvider.resolve().getAbsolutePath();
            Object virtualMachineInstance = virtualMachineType
                    .getMethod("attach", String.class)
                    .invoke(null, processId);
            try {
                virtualMachineType
                        .getMethod("loadAgent", String.class, String.class)
                        .invoke(virtualMachineInstance, agent, argument);
            } finally {
                virtualMachineType
                        .getMethod("detach")
                        .invoke(virtualMachineInstance);
            }
        } catch (RuntimeException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Error during attachment using: " + AttachmentProvider.DEFAULT, exception);
        }
    }

    /**
     * Attempts to resolve the location of the {@link Attacher} class for a self-attachment. Doing so avoids the creation of a temporary jar file.
     *
     * @return The self-resolved jar file or {@code null} if the jar file cannot be located.
     */
    private static File trySelfResolve() {
        try {
            ProtectionDomain protectionDomain = Attacher.class.getProtectionDomain();
            if (protectionDomain == null) {
                return null;
            }
            CodeSource codeSource = protectionDomain.getCodeSource();
            if (codeSource == null) {
                return null;
            }
            URL location = codeSource.getLocation();
            if (!location.getProtocol().equals("file")) {
                return null;
            }
            try {
                File file = new File(location.toURI());
                if (file.getPath().contains(AGENT_ARGUMENT_SEPARATOR)) {
                    return null;
                }
                return file;
            } catch (URISyntaxException ignored) {
                return new File(location.getPath());
            }
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * An attachment provider is responsible for making the Java attachment API available.
     */
    public interface AttachmentProvider {

        /**
         * The default attachment provider to be used.
         */
        AttachmentProvider DEFAULT = new Compound(ForModularizedVm.INSTANCE,
                ForJ9Vm.INSTANCE,
                ForStandardToolsJarVm.JVM_ROOT,
                ForStandardToolsJarVm.JDK_ROOT,
                ForStandardToolsJarVm.MACINTOSH,
                ForUserDefinedToolsJar.INSTANCE,
                ForEmulatedAttachment.INSTANCE);

        /**
         * Attempts the creation of an accessor for a specific JVM's attachment API.
         *
         * @return The accessor this attachment provider can supply for the currently running JVM.
         */
        Accessor attempt();

        /**
         * An accessor for a JVM's attachment API.
         */
        interface Accessor {

            /**
             * The name of the {@code VirtualMachine} class on any OpenJDK or Oracle JDK implementation.
             */
            String VIRTUAL_MACHINE_TYPE_NAME = "com.sun.tools.attach.VirtualMachine";

            /**
             * The name of the {@code VirtualMachine} class on IBM J9 VMs.
             */
            String VIRTUAL_MACHINE_TYPE_NAME_J9 = "com.ibm.tools.attach.VirtualMachine";

            /**
             * Determines if this accessor is applicable for the currently running JVM.
             *
             * @return {@code true} if this accessor is available.
             */
            boolean isAvailable();

            /**
             * Returns {@code true} if this accessor prohibits attachment to the same virtual machine in Java 9 and later.
             *
             * @return {@code true} if this accessor prohibits attachment to the same virtual machine in Java 9 and later.
             */
            boolean isExternalAttachmentRequired();

            /**
             * Returns a {@code VirtualMachine} class. This method must only be called for available accessors.
             *
             * @return The virtual machine type.
             */
            Class<?> getVirtualMachineType();

            /**
             * Returns a description of a virtual machine class for an external attachment.
             *
             * @return A description of the external attachment.
             */
            ExternalAttachment getExternalAttachment();

            /**
             * A canonical implementation of an unavailable accessor.
             */
            enum Unavailable implements Accessor {

                /**
                 * The singleton instance.
                 */
                INSTANCE;

                /**
                 * {@inheritDoc}
                 */
                public boolean isAvailable() {
                    return false;
                }

                /**
                 * {@inheritDoc}
                 */
                public boolean isExternalAttachmentRequired() {
                    throw new IllegalStateException("Cannot read the virtual machine type for an unavailable accessor");
                }

                /**
                 * {@inheritDoc}
                 */
                public Class<?> getVirtualMachineType() {
                    throw new IllegalStateException("Cannot read the virtual machine type for an unavailable accessor");
                }

                /**
                 * {@inheritDoc}
                 */
                public ExternalAttachment getExternalAttachment() {
                    throw new IllegalStateException("Cannot read the virtual machine type for an unavailable accessor");
                }
            }

            /**
             * Describes an external attachment to a Java virtual machine.
             */
            class ExternalAttachment {

                /**
                 * The fully-qualified binary name of the virtual machine type.
                 */
                private final String virtualMachineType;

                /**
                 * The class path elements required for loading the supplied virtual machine type.
                 */
                private final List<File> classPath;

                /**
                 * Creates an external attachment.
                 *
                 * @param virtualMachineType The fully-qualified binary name of the virtual machine type.
                 * @param classPath          The class path elements required for loading the supplied virtual machine type.
                 */
                public ExternalAttachment(String virtualMachineType, List<File> classPath) {
                    this.virtualMachineType = virtualMachineType;
                    this.classPath = classPath;
                }

                /**
                 * Returns the fully-qualified binary name of the virtual machine type.
                 *
                 * @return The fully-qualified binary name of the virtual machine type.
                 */
                public String getVirtualMachineType() {
                    return virtualMachineType;
                }

                /**
                 * Returns the class path elements required for loading the supplied virtual machine type.
                 *
                 * @return The class path elements required for loading the supplied virtual machine type.
                 */
                public List<File> getClassPath() {
                    return classPath;
                }
            }

            /**
             * A simple implementation of an accessible accessor.
             */
            abstract class Simple implements Accessor {

                /**
                 * A {@code VirtualMachine} class.
                 */
                protected final Class<?> virtualMachineType;

                /**
                 * Creates a new simple accessor.
                 *
                 * @param virtualMachineType A {@code VirtualMachine} class.
                 */
                protected Simple(Class<?> virtualMachineType) {
                    this.virtualMachineType = virtualMachineType;
                }

                /**
                 * <p>
                 * Creates an accessor by reading the process id from the JMX runtime bean and by attempting
                 * to load the {@code com.sun.tools.attach.VirtualMachine} class from the provided class loader.
                 * </p>
                 * <p>
                 * This accessor is supposed to work on any implementation of the OpenJDK or Oracle JDK.
                 * </p>
                 *
                 * @param classLoader A class loader that is capable of loading the virtual machine type.
                 * @param classPath   The class path required to load the virtual machine class.
                 * @return An appropriate accessor.
                 */
                public static Accessor of(ClassLoader classLoader, File... classPath) {
                    try {
                        return new Simple.WithExternalAttachment(Class.forName(VIRTUAL_MACHINE_TYPE_NAME,
                                false,
                                classLoader), Arrays.asList(classPath));
                    } catch (ClassNotFoundException ignored) {
                        return Unavailable.INSTANCE;
                    }
                }

                /**
                 * <p>
                 * Creates an accessor by reading the process id from the JMX runtime bean and by attempting
                 * to load the {@code com.ibm.tools.attach.VirtualMachine} class from the provided class loader.
                 * </p>
                 * <p>
                 * This accessor is supposed to work on any implementation of IBM's J9.
                 * </p>
                 *
                 * @return An appropriate accessor.
                 */
                public static Accessor ofJ9() {
                    try {
                        return new Simple.WithExternalAttachment(ClassLoader.getSystemClassLoader().loadClass(VIRTUAL_MACHINE_TYPE_NAME_J9),
                                Collections.<File>emptyList());
                    } catch (ClassNotFoundException ignored) {
                        return Unavailable.INSTANCE;
                    }
                }

                /**
                 * {@inheritDoc}
                 */
                public boolean isAvailable() {
                    return true;
                }

                /**
                 * {@inheritDoc}
                 */
                public Class<?> getVirtualMachineType() {
                    return virtualMachineType;
                }

                /**
                 * A simple implementation of an accessible accessor that allows for external attachment.
                 */
                protected static class WithExternalAttachment extends Simple {

                    /**
                     * The class path required for loading the virtual machine type.
                     */
                    private final List<File> classPath;

                    /**
                     * Creates a new simple accessor that allows for external attachment.
                     *
                     * @param virtualMachineType The {@code com.sun.tools.attach.VirtualMachine} class.
                     * @param classPath          The class path required for loading the virtual machine type.
                     */
                    public WithExternalAttachment(Class<?> virtualMachineType, List<File> classPath) {
                        super(virtualMachineType);
                        this.classPath = classPath;
                    }

                    /**
                     * {@inheritDoc}
                     */
                    public boolean isExternalAttachmentRequired() {
                        return true;
                    }

                    /**
                     * {@inheritDoc}
                     */
                    public ExternalAttachment getExternalAttachment() {
                        return new ExternalAttachment(virtualMachineType.getName(), classPath);
                    }
                }

                /**
                 * A simple implementation of an accessible accessor that attaches using a virtual machine emulation that does not require external attachment.
                 */
                protected static class WithDirectAttachment extends Simple {

                    /**
                     * Creates a new simple accessor that implements direct attachment.
                     *
                     * @param virtualMachineType A {@code VirtualMachine} class.
                     */
                    public WithDirectAttachment(Class<?> virtualMachineType) {
                        super(virtualMachineType);
                    }

                    /**
                     * {@inheritDoc}
                     */
                    public boolean isExternalAttachmentRequired() {
                        return false;
                    }

                    /**
                     * {@inheritDoc}
                     */
                    public ExternalAttachment getExternalAttachment() {
                        throw new IllegalStateException("Cannot apply external attachment");
                    }
                }
            }
        }

        /**
         * An attachment provider that locates the attach API directly from the system class loader, as possible since
         * introducing the Java module system via the {@code jdk.attach} module.
         */
        enum ForModularizedVm implements AttachmentProvider {

            /**
             * The singleton instance.
             */
            INSTANCE;

            /**
             * {@inheritDoc}
             */
            public Accessor attempt() {
                return Accessor.Simple.of(ClassLoader.getSystemClassLoader());
            }
        }

        /**
         * An attachment provider that locates the attach API directly from the system class loader expecting
         * an IBM J9 VM.
         */
        enum ForJ9Vm implements AttachmentProvider {

            /**
             * The singleton instance.
             */
            INSTANCE;

            /**
             * {@inheritDoc}
             */
            public Accessor attempt() {
                return Accessor.Simple.ofJ9();
            }
        }

        /**
         * An attachment provider that is dependant on the existence of a <i>tools.jar</i> file on the local
         * file system.
         */
        enum ForStandardToolsJarVm implements AttachmentProvider {

            /**
             * An attachment provider that locates the <i>tools.jar</i> from a Java home directory.
             */
            JVM_ROOT("../lib/tools.jar"),

            /**
             * An attachment provider that locates the <i>tools.jar</i> from a Java installation directory.
             * In practice, several virtual machines do not return the JRE's location for the
             * <i>java.home</i> property against the property's specification.
             */
            JDK_ROOT("lib/tools.jar"),

            /**
             * An attachment provider that locates the <i>tools.jar</i> as it is set for several JVM
             * installations on Apple Macintosh computers.
             */
            MACINTOSH("../Classes/classes.jar");

            /**
             * The Java home system property.
             */
            private static final String JAVA_HOME_PROPERTY = "java.home";

            /**
             * The path to the <i>tools.jar</i> file, starting from the Java home directory.
             */
            private final String toolsJarPath;

            /**
             * Creates a new attachment provider that loads the virtual machine class from the <i>tools.jar</i>.
             *
             * @param toolsJarPath The path to the <i>tools.jar</i> file, starting from the Java home directory.
             */
            ForStandardToolsJarVm(String toolsJarPath) {
                this.toolsJarPath = toolsJarPath;
            }

            /**
             * {@inheritDoc}
             */
            public Accessor attempt() {
                File toolsJar = new File(System.getProperty(JAVA_HOME_PROPERTY), toolsJarPath);
                try {
                    return toolsJar.isFile() && toolsJar.canRead()
                            ? Accessor.Simple.of(new URLClassLoader(new URL[]{toolsJar.toURI().toURL()}, BOOTSTRAP_CLASS_LOADER), toolsJar)
                            : Accessor.Unavailable.INSTANCE;
                } catch (MalformedURLException exception) {
                    throw new IllegalStateException("Could not represent " + toolsJar + " as URL");
                }
            }
        }

        /**
         * An attachment provider that attempts to locate a {@code tools.jar} from a custom location set via a system property.
         */
        enum ForUserDefinedToolsJar implements AttachmentProvider {

            /**
             * The singelton instance.
             */
            INSTANCE;

            /**
             * The property being read for locating {@code tools.jar}.
             */
            public static final String PROPERTY = "net.bytebuddy.agent.toolsjar";

            /**
             * {@inheritDoc}
             */
            public Accessor attempt() {
                String location = System.getProperty(PROPERTY);
                if (location == null) {
                    return Accessor.Unavailable.INSTANCE;
                } else {
                    File toolsJar = new File(location);
                    try {
                        return Accessor.Simple.of(new URLClassLoader(new URL[]{toolsJar.toURI().toURL()}, BOOTSTRAP_CLASS_LOADER), toolsJar);
                    } catch (MalformedURLException exception) {
                        throw new IllegalStateException("Could not represent " + toolsJar + " as URL");
                    }
                }
            }
        }

        /**
         * An attachment provider that uses Byte Buddy's attachment API emulation. To use this feature, JNA is required.
         */
        enum ForEmulatedAttachment implements AttachmentProvider {

            /**
             * The singleton instance.
             */
            INSTANCE;

            /**
             * {@inheritDoc}
             */
            public Accessor attempt() {
                try {
                    return new Accessor.Simple.WithDirectAttachment(VirtualMachine.Resolver.INSTANCE.get());
                } catch (Throwable ignored) {
                    return Accessor.Unavailable.INSTANCE;
                }
            }
        }

        /**
         * A compound attachment provider that attempts the attachment by delegation to other providers. If
         * none of the providers of this compound provider is capable of providing a valid accessor, an
         * non-available accessor is returned.
         */
        class Compound implements AttachmentProvider {

            /**
             * A list of attachment providers in the order of their application.
             */
            private final List<AttachmentProvider> attachmentProviders;

            /**
             * Creates a new compound attachment provider.
             *
             * @param attachmentProvider A list of attachment providers in the order of their application.
             */
            public Compound(AttachmentProvider... attachmentProvider) {
                this(Arrays.asList(attachmentProvider));
            }

            /**
             * Creates a new compound attachment provider.
             *
             * @param attachmentProviders A list of attachment providers in the order of their application.
             */
            public Compound(List<? extends AttachmentProvider> attachmentProviders) {
                this.attachmentProviders = new ArrayList<AttachmentProvider>();
                for (AttachmentProvider attachmentProvider : attachmentProviders) {
                    if (attachmentProvider instanceof Compound) {
                        this.attachmentProviders.addAll(((Compound) attachmentProvider).attachmentProviders);
                    } else {
                        this.attachmentProviders.add(attachmentProvider);
                    }
                }
            }

            /**
             * {@inheritDoc}
             */
            public Accessor attempt() {
                for (AttachmentProvider attachmentProvider : attachmentProviders) {
                    Accessor accessor = attachmentProvider.attempt();
                    if (accessor.isAvailable()) {
                        return accessor;
                    }
                }
                return Accessor.Unavailable.INSTANCE;
            }
        }
    }

    /**
     * A process provider is responsible for providing the process id of the current VM.
     */
    public interface ProcessProvider {

        /**
         * Resolves a process id for the current JVM.
         *
         * @return The resolved process id.
         */
        String resolve();

        /**
         * Supplies the current VM's process id.
         */
        enum ForCurrentVm implements ProcessProvider {

            /**
             * The singleton instance.
             */
            INSTANCE;

            /**
             * The best process provider for the current VM.
             */
            private final ProcessProvider dispatcher;

            /**
             * Creates a process provider that supplies the current VM's process id.
             */
            ForCurrentVm() {
                dispatcher = ForJava9CapableVm.make();
            }

            /**
             * {@inheritDoc}
             */
            public String resolve() {
                return dispatcher.resolve();
            }

            /**
             * A process provider for a legacy VM that reads the process id from its JMX properties. This strategy
             * is only used prior to Java 9 such that the <i>java.management</i> module never is resolved, even if
             * the module system is used, as the module system was not available in any relevant JVM version.
             */
            protected enum ForLegacyVm implements ProcessProvider {

                /**
                 * The singleton instance.
                 */
                INSTANCE;

                /**
                 * {@inheritDoc}
                 */
                public String resolve() {
                    String runtimeName;
                    try {
                        Method method = Class.forName("java.lang.management.ManagementFactory").getMethod("getRuntimeMXBean");
                        runtimeName = (String) method.getReturnType().getMethod("getName").invoke(method.invoke(null));
                    } catch (Exception exception) {
                        throw new IllegalStateException("Failed to access VM name via management factory", exception);
                    }
                    int processIdIndex = runtimeName.indexOf('@');
                    if (processIdIndex == -1) {
                        throw new IllegalStateException("Cannot extract process id from runtime management bean");
                    } else {
                        return runtimeName.substring(0, processIdIndex);
                    }
                }
            }

            /**
             * A process provider for a Java 9 capable VM with access to the introduced process API.
             */
            protected static class ForJava9CapableVm implements ProcessProvider {

                /**
                 * The {@code java.lang.ProcessHandle#current()} method.
                 */
                private final Method current;

                /**
                 * The {@code java.lang.ProcessHandle#pid()} method.
                 */
                private final Method pid;

                /**
                 * Creates a new Java 9 capable dispatcher for reading the current process's id.
                 *
                 * @param current The {@code java.lang.ProcessHandle#current()} method.
                 * @param pid     The {@code java.lang.ProcessHandle#pid()} method.
                 */
                protected ForJava9CapableVm(Method current, Method pid) {
                    this.current = current;
                    this.pid = pid;
                }

                /**
                 * Attempts to create a dispatcher for a Java 9 VM and falls back to a legacy dispatcher
                 * if this is not possible.
                 *
                 * @return A dispatcher for the current VM.
                 */
                public static ProcessProvider make() {
                    try {
                        return new ForJava9CapableVm(Class.forName("java.lang.ProcessHandle").getMethod("current"),
                                Class.forName("java.lang.ProcessHandle").getMethod("pid"));
                    } catch (Exception ignored) {
                        return ForLegacyVm.INSTANCE;
                    }
                }

                /**
                 * {@inheritDoc}
                 */
                public String resolve() {
                    try {
                        return pid.invoke(current.invoke(null)).toString();
                    } catch (IllegalAccessException exception) {
                        throw new IllegalStateException("Cannot access Java 9 process API", exception);
                    } catch (InvocationTargetException exception) {
                        throw new IllegalStateException("Error when accessing Java 9 process API", exception.getTargetException());
                    }
                }
            }
        }
    }

    /**
     * An agent provider is responsible for handling and providing the jar file of an agent that is being attached.
     */
    protected interface AgentProvider {

        /**
         * Provides an agent jar file for attachment.
         *
         * @return The provided agent.
         * @throws IOException If the agent cannot be written to disk.
         */
        File resolve() throws IOException;

        /**
         * An agent provider that supplies an existing agent that is not deleted after attachment.
         */
        class ForExistingAgent implements AgentProvider {

            /**
             * The supplied agent.
             */
            private final File agent;

            /**
             * Creates an agent provider for an existing agent.
             *
             * @param agent The supplied agent.
             */
            protected ForExistingAgent(File agent) {
                this.agent = agent;
            }

            /**
             * {@inheritDoc}
             */
            public File resolve() {
                return agent;
            }
        }
    }

    /**
     * An attachment evaluator is responsible for deciding if an agent can be attached from the current process.
     */
    protected interface AttachmentTypeEvaluator {

        /**
         * Checks if the current VM requires external attachment for the supplied process id.
         *
         * @param processId The process id of the process to which to attach.
         * @return {@code true} if the current VM requires external attachment for the supplied process.
         */
        boolean requiresExternalAttachment(String processId);

        /**
         * An installation action for creating an attachment type evaluator.
         */
        enum InstallationAction implements PrivilegedAction<AttachmentTypeEvaluator> {

            /**
             * The singleton instance.
             */
            INSTANCE;

            /**
             * The OpenJDK's property for specifying the legality of self-attachment.
             */
            private static final String JDK_ALLOW_SELF_ATTACH = "jdk.attach.allowAttachSelf";

            /**
             * {@inheritDoc}
             */
            public AttachmentTypeEvaluator run() {
                try {
                    if (Boolean.getBoolean(JDK_ALLOW_SELF_ATTACH)) {
                        return Disabled.INSTANCE;
                    } else {
                        return new ForJava9CapableVm(Class.forName("java.lang.ProcessHandle").getMethod("current"),
                                Class.forName("java.lang.ProcessHandle").getMethod("pid"));
                    }
                } catch (Exception ignored) {
                    return Disabled.INSTANCE;
                }
            }
        }

        /**
         * An attachment type evaluator that never requires external attachment.
         */
        enum Disabled implements AttachmentTypeEvaluator {

            /**
             * The singleton instance.
             */
            INSTANCE;

            /**
             * {@inheritDoc}
             */
            public boolean requiresExternalAttachment(String processId) {
                return false;
            }
        }

        /**
         * An attachment type evaluator that checks a process id against the current process id.
         */
        class ForJava9CapableVm implements AttachmentTypeEvaluator {

            /**
             * The {@code java.lang.ProcessHandle#current()} method.
             */
            private final Method current;

            /**
             * The {@code java.lang.ProcessHandle#pid()} method.
             */
            private final Method pid;

            /**
             * Creates a new attachment type evaluator.
             *
             * @param current The {@code java.lang.ProcessHandle#current()} method.
             * @param pid     The {@code java.lang.ProcessHandle#pid()} method.
             */
            protected ForJava9CapableVm(Method current, Method pid) {
                this.current = current;
                this.pid = pid;
            }

            /**
             * {@inheritDoc}
             */
            public boolean requiresExternalAttachment(String processId) {
                try {
                    return pid.invoke(current.invoke(null)).toString().equals(processId);
                } catch (IllegalAccessException exception) {
                    throw new IllegalStateException("Cannot access Java 9 process API", exception);
                } catch (InvocationTargetException exception) {
                    throw new IllegalStateException("Error when accessing Java 9 process API", exception.getTargetException());
                }
            }
        }
    }

    /**
     * Represents a discovered Java process on the local host.
     */
    public static class JavaProcessDescriptor {

        /**
         * The process ID.
         */
        private final String pid;

        /**
         * The main class name or JAR path, may be empty if unknown.
         */
        private final String mainClass;

        /**
         * The JVM type identifier, e.g. "HotSpot" or "OpenJ9".
         */
        private final String vmType;

        /**
         * Creates a new Java process descriptor.
         *
         * @param pid       The process ID.
         * @param mainClass The main class name or JAR path, may be empty if unknown.
         * @param vmType    The JVM type, e.g. "HotSpot" or "OpenJ9".
         */
        public JavaProcessDescriptor(String pid, String mainClass, String vmType) {
            this.pid = pid;
            this.mainClass = mainClass;
            this.vmType = vmType;
        }

        /**
         * Returns the process ID.
         *
         * @return The process ID.
         */
        public String getPid() {
            return pid;
        }

        /**
         * Returns the main class name or JAR path. May be empty if unknown.
         *
         * @return The main class name.
         */
        public String getMainClass() {
            return mainClass;
        }

        /**
         * Returns the JVM type identifier.
         *
         * @return The JVM type, e.g. "HotSpot" or "OpenJ9".
         */
        public String getVmType() {
            return vmType;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(pid);
            if (mainClass.length() > 0) {
                sb.append(' ').append(mainClass);
            }
            sb.append(" (").append(vmType).append(')');
            return sb.toString();
        }
    }

    /**
     * Discovers running HotSpot JVM processes by scanning {@code hsperfdata_<user>} directories
     * in the system temporary folder and parsing PerfData v2 binary files.
     */
    private static class HotSpotProcessDiscovery {

        /**
         * The PerfData magic number: {@code 0xcafec0c0}.
         */
        private static final int PERFDATA_MAGIC = 0xcafec0c0;

        /**
         * The directory name prefix for HotSpot PerfData user directories.
         */
        private static final String HSPERFDATA_PREFIX = "hsperfdata_";

        /**
         * The PerfData entry name for the Java command line.
         */
        private static final String JAVA_COMMAND_KEY = "sun.rt.javaCommand";

        /**
         * The data units value for STRING type entries.
         */
        private static final byte UNITS_STRING = 5;

        /**
         * Maximum PerfData file size to read (1 MB), as a safety bound.
         */
        private static final int MAX_PERFDATA_SIZE = 1024 * 1024;

        /**
         * Minimum PerfData file size (v2 prologue is 32 bytes).
         */
        private static final int MIN_PERFDATA_SIZE = 32;

        /**
         * The size of a PerfData v2 entry header in bytes.
         */
        private static final int ENTRY_HEADER_SIZE = 20;

        /**
         * Discovers all HotSpot JVM processes visible to the current user.
         *
         * @return A list of discovered HotSpot Java process descriptors.
         */
        static List<JavaProcessDescriptor> discover() {
            List<JavaProcessDescriptor> result = new ArrayList<JavaProcessDescriptor>();
            Set<String> seen = new HashSet<String>();
            for (File tmpDir : getTempDirectories()) {
                if (!tmpDir.isDirectory()) {
                    continue;
                }
                File[] userDirs = tmpDir.listFiles();
                if (userDirs == null) {
                    continue;
                }
                for (File userDir : userDirs) {
                    if (!userDir.isDirectory() || !userDir.getName().startsWith(HSPERFDATA_PREFIX)) {
                        continue;
                    }
                    File[] pidFiles = userDir.listFiles();
                    if (pidFiles == null) {
                        continue;
                    }
                    for (File pidFile : pidFiles) {
                        String fileName = pidFile.getName();
                        if (!pidFile.isFile() || !pidFile.canRead() || !isNumeric(fileName)) {
                            continue;
                        }
                        if (!seen.add(fileName)) {
                            continue;
                        }
                        String javaCommand = parsePerfData(pidFile);
                        result.add(new JavaProcessDescriptor(fileName, extractMainClass(javaCommand), "HotSpot"));
                    }
                }
            }
            return result;
        }

        /**
         * Returns the list of temporary directories to scan for HotSpot PerfData files.
         * On Windows, uses {@code java.io.tmpdir}. On Linux/macOS, uses {@code /tmp}
         * and also {@code java.io.tmpdir} if it differs.
         *
         * @return A list of temporary directories.
         */
        private static List<File> getTempDirectories() {
            List<File> dirs = new ArrayList<File>();
            String osName = System.getProperty("os.name", "");
            if (osName.startsWith("Windows")) {
                dirs.add(new File(System.getProperty("java.io.tmpdir")));
            } else {
                dirs.add(new File("/tmp"));
                String javaIoTmpDir = System.getProperty("java.io.tmpdir");
                if (javaIoTmpDir != null && !"/tmp".equals(javaIoTmpDir) && !"/tmp/".equals(javaIoTmpDir)) {
                    dirs.add(new File(javaIoTmpDir));
                }
            }
            return dirs;
        }

        /**
         * Parses a HotSpot PerfData v2 binary file to extract the value of
         * {@code sun.rt.javaCommand}.
         * <p>
         * The PerfData v2 binary format consists of a 32-byte prologue followed
         * by a sequence of variable-length entries. Each entry contains a name
         * and a data value. This method iterates through entries looking for
         * the {@code sun.rt.javaCommand} entry.
         * </p>
         *
         * @param file The PerfData file to parse.
         * @return The value of {@code sun.rt.javaCommand}, or empty string if not found.
         */
        private static String parsePerfData(File file) {
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(file);
                long fileLength = file.length();
                if (fileLength < MIN_PERFDATA_SIZE || fileLength > MAX_PERFDATA_SIZE) {
                    return "";
                }
                byte[] data = new byte[(int) fileLength];
                int totalRead = 0;
                int bytesRead;
                while (totalRead < data.length
                        && (bytesRead = fis.read(data, totalRead, data.length - totalRead)) != -1) {
                    totalRead += bytesRead;
                }
                if (totalRead < MIN_PERFDATA_SIZE) {
                    return "";
                }

                ByteBuffer buffer = ByteBuffer.wrap(data, 0, totalRead);
                // Magic number is always stored in big-endian
                buffer.order(ByteOrder.BIG_ENDIAN);
                int magic = buffer.getInt();             // offset 0
                if (magic != PERFDATA_MAGIC) {
                    return "";
                }

                byte byteOrder = buffer.get();           // offset 4
                if (byteOrder == 1) {
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                }

                byte majorVersion = buffer.get();        // offset 5
                buffer.get();                            // offset 6: minor version
                buffer.get();                            // offset 7: accessible / reserved

                if (majorVersion < 2) {
                    // Only PerfData v2 format is supported
                    return "";
                }

                // v2 prologue fields
                buffer.getInt();                         // offset 8: used
                buffer.getInt();                         // offset 12: overflow
                buffer.getLong();                        // offset 16: mod_time_stamp
                int entryOffset = buffer.getInt();       // offset 24: entry_offset
                int numEntries = buffer.getInt();        // offset 28: num_entries

                // Iterate through PerfData entries
                int pos = entryOffset;
                for (int i = 0; i < numEntries && pos >= 0 && pos + ENTRY_HEADER_SIZE <= totalRead; i++) {
                    buffer.position(pos);
                    int entryLength = buffer.getInt();
                    if (entryLength <= 0 || pos + entryLength > totalRead) {
                        break;
                    }

                    int nameOffset = buffer.getInt();
                    buffer.getInt();                     // vector_length
                    buffer.get();                        // data_type
                    buffer.get();                        // flags
                    byte dataUnits = buffer.get();       // data_units
                    buffer.get();                        // data_variability
                    int dataOffset = buffer.getInt();

                    // Read the entry name (null-terminated UTF-8 string)
                    int nameStart = pos + nameOffset;
                    if (nameStart < 0 || nameStart >= totalRead) {
                        pos += entryLength;
                        continue;
                    }
                    int nameEnd = nameStart;
                    while (nameEnd < totalRead && data[nameEnd] != 0) {
                        nameEnd++;
                    }
                    String name = new String(data, nameStart, nameEnd - nameStart, "UTF-8");

                    if (JAVA_COMMAND_KEY.equals(name) && dataUnits == UNITS_STRING) {
                        // Read the string value
                        int dataStart = pos + dataOffset;
                        if (dataStart < 0 || dataStart >= totalRead) {
                            return "";
                        }
                        int dataEnd = dataStart;
                        while (dataEnd < totalRead && data[dataEnd] != 0) {
                            dataEnd++;
                        }
                        return new String(data, dataStart, dataEnd - dataStart, "UTF-8");
                    }

                    pos += entryLength;
                }

                return "";
            } catch (Exception ignored) {
                return "";
            } finally {
                if (fis != null) {
                    try {
                        fis.close();
                    } catch (IOException ignored) {
                        /* do nothing */
                    }
                }
            }
        }

        /**
         * Checks if a string consists entirely of digit characters.
         *
         * @param str The string to check.
         * @return {@code true} if the string is non-empty and contains only digits.
         */
        private static boolean isNumeric(String str) {
            if (str == null || str.isEmpty()) {
                return false;
            }
            for (int i = 0; i < str.length(); i++) {
                if (str.charAt(i) < '0' || str.charAt(i) > '9') {
                    return false;
                }
            }
            return true;
        }

        /**
         * Extracts the main class name from a {@code sun.rt.javaCommand} value.
         * The value format is typically {@code "mainClass arg1 arg2 ..."} or
         * {@code "/path/to/app.jar arg1 arg2 ..."}. This method returns the
         * first space-delimited token.
         *
         * @param javaCommand The full Java command string.
         * @return The main class or JAR name, or empty string if input is empty.
         */
        private static String extractMainClass(String javaCommand) {
            if (javaCommand == null || javaCommand.isEmpty()) {
                return "";
            }
            int spaceIndex = javaCommand.indexOf(' ');
            return spaceIndex > 0 ? javaCommand.substring(0, spaceIndex) : javaCommand;
        }
    }

    /**
     * Discovers running OpenJ9 JVM processes by scanning {@code .com_ibm_tools_attach} directories
     * and reading {@code attachInfo} property files.
     */
    private static class OpenJ9ProcessDiscovery {

        /**
         * The directory name used by OpenJ9 for attach API information.
         */
        private static final String ATTACH_DIR_NAME = ".com_ibm_tools_attach";

        /**
         * The file name containing process attach information within each VM directory.
         */
        private static final String ATTACH_INFO_FILE = "attachInfo";

        /**
         * Discovers all OpenJ9 JVM processes visible to the current user.
         *
         * @return A list of discovered OpenJ9 Java process descriptors.
         */
        static List<JavaProcessDescriptor> discover() {
            List<JavaProcessDescriptor> result = new ArrayList<JavaProcessDescriptor>();
            for (File attachDir : getAttachDirectories()) {
                if (!attachDir.isDirectory()) {
                    continue;
                }
                File[] vmDirs = attachDir.listFiles();
                if (vmDirs == null) {
                    continue;
                }
                for (File vmDir : vmDirs) {
                    if (!vmDir.isDirectory()) {
                        continue;
                    }
                    File attachInfo = new File(vmDir, ATTACH_INFO_FILE);
                    if (!attachInfo.isFile() || !attachInfo.canRead()) {
                        continue;
                    }
                    FileInputStream fis = null;
                    try {
                        Properties props = new Properties();
                        fis = new FileInputStream(attachInfo);
                        props.load(fis);
                        String pid = props.getProperty("processId");
                        String displayName = props.getProperty("displayName", "");
                        if (pid != null && pid.length() > 0) {
                            result.add(new JavaProcessDescriptor(pid, displayName, "OpenJ9"));
                        }
                    } catch (Exception ignored) {
                        /* do nothing */
                    } finally {
                        if (fis != null) {
                            try {
                                fis.close();
                            } catch (IOException ignored) {
                                /* do nothing */
                            }
                        }
                    }
                }
            }
            return result;
        }

        /**
         * Returns the list of directories to scan for OpenJ9 attach information.
         * On Windows, uses {@code java.io.tmpdir}. On Linux/macOS, uses {@code /tmp}
         * and also {@code java.io.tmpdir} if it differs. Additionally checks the
         * {@code com.ibm.tools.attach.directory} system property.
         *
         * @return A list of attach directories to scan.
         */
        private static List<File> getAttachDirectories() {
            List<File> dirs = new ArrayList<File>();
            String osName = System.getProperty("os.name", "");
            if (osName.startsWith("Windows")) {
                dirs.add(new File(System.getProperty("java.io.tmpdir"), ATTACH_DIR_NAME));
            } else {
                dirs.add(new File("/tmp", ATTACH_DIR_NAME));
                String javaIoTmpDir = System.getProperty("java.io.tmpdir");
                if (javaIoTmpDir != null && !"/tmp".equals(javaIoTmpDir) && !"/tmp/".equals(javaIoTmpDir)) {
                    dirs.add(new File(javaIoTmpDir, ATTACH_DIR_NAME));
                }
            }
            String ibmAttachDir = System.getProperty("com.ibm.tools.attach.directory");
            if (ibmAttachDir != null) {
                dirs.add(new File(ibmAttachDir));
            }
            return dirs;
        }
    }
}
