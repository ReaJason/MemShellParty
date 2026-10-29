package com.reajason.javaweb.fileless;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/** Win64 native stubs used by the attach bridge and the temporary JNI trigger. */
final class WindowsX64Stub {
    private WindowsX64Stub() {
    }

    static byte[] resolveModules(long outputAddress) {
        Code code = new Code();
        Label exportLoop = new Label();
        Label exportNext = new Label();
        Label exportFound = new Label();
        Label failure = new Label();
        Label done = new Label();

        code.bytes(0x55, 0x48, 0x89, 0xe5);       // push rbp; mov rbp, rsp
        code.bytes(0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55);
        code.bytes(0x48, 0x83, 0xec, 0x48);       // shadow space and 40 bytes of locals
        code.bytes(0x49, 0xbc);
        code.longValue(outputAddress);
        code.status(1);

        code.bytes(0x48, 0x31, 0xc9);             // PEB -> third load-order module (kernel32)
        code.bytes(0x65, 0x48, 0x8b, 0x41, 0x60);
        code.bytes(0x48, 0x8b, 0x40, 0x18);
        code.bytes(0x48, 0x8b, 0x70, 0x20);
        code.bytes(0x48, 0x8b, 0x06);
        code.bytes(0x48, 0x8b, 0x30);
        code.bytes(0x48, 0x8b, 0x36);
        code.bytes(0x48, 0x8b, 0x5e, 0x20);       // rbx = kernel32 image base
        code.status(2);

        code.bytes(0x44, 0x8b, 0x43, 0x3c);       // PE export directory
        code.bytes(0x48, 0x89, 0xda, 0x4c, 0x01, 0xc2);
        code.bytes(0x44, 0x8b, 0x82, 0x88, 0, 0, 0);
        code.bytes(0x49, 0x01, 0xd8);
        code.bytes(0x41, 0x8b, 0x70, 0x20);
        code.bytes(0x48, 0x01, 0xde);             // rsi = export names
        code.bytes(0x48, 0x31, 0xc9);
        code.bind(exportLoop);
        code.bytes(0x41, 0x3b, 0x48, 0x18);       // index < NumberOfNames
        code.jump(0x83, failure);
        code.bytes(0x8b, 0x04, 0x8e, 0x48, 0x01, 0xd8);
        code.bytes(0x49, 0xb9);
        code.longValue(0x41636f7250746547L);      // GetProcA
        code.bytes(0x4c, 0x39, 0x08);
        code.jump(0x85, exportNext);
        code.bytes(0x81, 0x78, 0x08, 0x64, 0x64, 0x72, 0x65); // ddre
        code.jump(0x85, exportNext);
        code.bytes(0x66, 0x81, 0x78, 0x0c, 0x73, 0x73);       // ss
        code.jump(0x85, exportNext);
        code.bytes(0x80, 0x78, 0x0e, 0x00);
        code.jump(0x84, exportFound);
        code.bind(exportNext);
        code.bytes(0x48, 0xff, 0xc1);
        code.jump(0xe9, exportLoop);
        code.bind(exportFound);
        code.bytes(0x41, 0x8b, 0x70, 0x24, 0x48, 0x01, 0xde);
        code.bytes(0x0f, 0xb7, 0x0c, 0x4e);
        code.bytes(0x41, 0x8b, 0x70, 0x1c, 0x48, 0x01, 0xde);
        code.bytes(0x8b, 0x04, 0x8e, 0x48, 0x01, 0xd8);
        code.bytes(0x48, 0x89, 0xc7);             // rdi = GetProcAddress
        code.status(3);

        code.stackString("LoadLibraryA", 0x20);
        code.bytes(0x48, 0x89, 0xd9, 0x48, 0x8d, 0x54, 0x24, 0x20);
        code.callRegister(7);
        code.bytes(0x48, 0x85, 0xc0);
        code.jump(0x84, failure);
        code.bytes(0x49, 0x89, 0xc5);             // r13 = LoadLibraryA
        code.status(4);

        code.stackString("jvm.dll", 0x20);
        code.bytes(0x48, 0x8d, 0x4c, 0x24, 0x20);
        code.callRegister(13);
        code.bytes(0x48, 0x85, 0xc0);
        code.jump(0x84, failure);
        code.storeOutput(0);
        code.status(5);

        code.stackString("instrument.dll", 0x20);
        code.bytes(0x48, 0x8d, 0x4c, 0x24, 0x20);
        code.callRegister(13);
        code.bytes(0x48, 0x85, 0xc0);
        code.jump(0x84, failure);
        code.storeOutput(8);
        code.status(6);

        code.stackString("JNI_GetCreatedJavaVMs", 0x20);
        code.bytes(0x49, 0x8b, 0x0c, 0x24, 0x48, 0x8d, 0x54, 0x24, 0x20);
        code.callRegister(7);
        code.bytes(0x48, 0x85, 0xc0);
        code.jump(0x84, failure);
        code.storeOutput(16);
        code.status(7);

        code.stackString("WriteProcessMemory", 0x20);
        code.bytes(0x48, 0x89, 0xd9, 0x48, 0x8d, 0x54, 0x24, 0x20);
        code.callRegister(7);
        code.bytes(0x48, 0x85, 0xc0);
        code.jump(0x84, failure);
        code.storeOutput(24);
        code.status(8);

        code.stackString("FlushInstructionCache", 0x20);
        code.bytes(0x48, 0x89, 0xd9, 0x48, 0x8d, 0x54, 0x24, 0x20);
        code.callRegister(7);
        code.bytes(0x48, 0x85, 0xc0);
        code.jump(0x84, failure);
        code.storeOutput(32);
        code.status(0x100);
        code.jump(0xe9, done);

        code.bind(failure);
        code.bind(done);
        code.bytes(0x31, 0xc0);                   // attach enqueue sees a completed thread
        code.bytes(0x48, 0x83, 0xc4, 0x48);
        code.bytes(0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0x5d, 0xc3);
        return code.toByteArray();
    }

    static byte[] acquireInstrumentation(long jniGetCreatedJavaVMs,
                                         long createNewJPLISAgent,
                                         long addRedefineClassesCapability,
                                         long retransformableEnvironment,
                                         long createInstrumentationImpl,
                                         long setLivePhaseEventHandlers,
                                         int instrumentationImplOffset,
                                         int printWarningOffset) {
        if (instrumentationImplOffset < 0 || instrumentationImplOffset > 127) {
            throw new IllegalArgumentException("Invalid JPLIS InstrumentationImpl offset");
        }
        if (printWarningOffset < -1 || printWarningOffset > 127) {
            throw new IllegalArgumentException("Invalid JPLIS printWarning offset");
        }
        Code code = new Code();
        Label failure = new Label();
        Label done = new Label();
        code.bytes(0x55, 0x48, 0x89, 0xe5);
        code.bytes(0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57);
        code.bytes(0x48, 0x83, 0xec, 0x38);
        code.bytes(0x49, 0x89, 0xcc);             // r12 = JNIEnv

        code.bytes(0x48, 0x8d, 0x4c, 0x24, 0x20); // JavaVM **
        code.bytes(0xba, 1, 0, 0, 0);
        code.bytes(0x4c, 0x8d, 0x44, 0x24, 0x30); // jint *count
        code.call(jniGetCreatedJavaVMs);
        code.bytes(0x85, 0xc0);
        code.jump(0x85, failure);
        code.bytes(0x83, 0x7c, 0x24, 0x30, 1);
        code.jump(0x8c, failure);

        code.bytes(0x48, 0x8b, 0x4c, 0x24, 0x20); // JavaVM
        code.bytes(0x48, 0x8d, 0x54, 0x24, 0x28); // JPLISAgent **
        code.call(createNewJPLISAgent);
        code.bytes(0x85, 0xc0);
        code.jump(0x85, failure);

        code.loadAgent();
        code.call(addRedefineClassesCapability);
        code.loadAgent();
        code.call(retransformableEnvironment);
        code.bytes(0x48, 0x85, 0xc0);
        code.jump(0x84, failure);

        if (printWarningOffset >= 0) {
            code.bytes(0x48, 0x8b, 0x44, 0x24, 0x28);
            code.bytes(0xc6, 0x40, printWarningOffset, 0);
        }
        code.bytes(0x4c, 0x89, 0xe1);             // JNIEnv
        code.bytes(0x48, 0x8b, 0x54, 0x24, 0x28); // agent
        code.call(createInstrumentationImpl);
        code.bytes(0x84, 0xc0);
        code.jump(0x84, failure);
        code.loadAgent();
        code.call(setLivePhaseEventHandlers);
        code.bytes(0x84, 0xc0);
        code.jump(0x84, failure);

        code.bytes(0x48, 0x8b, 0x44, 0x24, 0x28);
        code.bytes(0x48, 0x8b, 0x40, instrumentationImplOffset);
        code.bytes(0x48, 0x85, 0xc0);
        code.jump(0x84, failure);
        code.jump(0xe9, done);
        code.bind(failure);
        code.bytes(0x31, 0xc0);
        code.bind(done);
        code.bytes(0x48, 0x83, 0xc4, 0x38);
        code.bytes(0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5b, 0x5d, 0xc3);
        return code.toByteArray();
    }

    static byte[] writeMemory(long destination, byte[] replacement,
                              long writeProcessMemory, long flushInstructionCache,
                              long statusAddress) {
        if (replacement == null || replacement.length == 0 || replacement.length > 512) {
            throw new IllegalArgumentException("Invalid native replacement size");
        }
        Code code = new Code();
        Label failure = new Label();
        Label done = new Label();
        Label data = new Label();
        code.bytes(0x55, 0x48, 0x89, 0xe5);
        code.bytes(0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57);
        code.bytes(0x48, 0x83, 0xec, 0x28);
        code.bytes(0x49, 0xbc);
        code.longValue(statusAddress);
        code.bytes(0x49, 0xbd);
        code.longValue(destination);
        code.bytes(0x49, 0xbf);
        code.longValue(writeProcessMemory);
        code.bytes(0x48, 0xbb);
        code.longValue(flushInstructionCache);
        code.bytes(0x49, 0xc7, 0xc6);
        code.intValue(replacement.length);

        code.bytes(0x48, 0x83, 0xc9, 0xff);       // GetCurrentProcess() pseudo-handle
        code.bytes(0x4c, 0x89, 0xea);             // destination
        code.ripLea(8, data);                     // replacement
        code.bytes(0x45, 0x89, 0xf1);             // length (r9d = r14d)
        code.bytes(0x48, 0x8d, 0x44, 0x24, 0x28); // &written
        code.bytes(0x48, 0x89, 0x44, 0x24, 0x20); // fifth argument
        code.callRegister(15);
        code.bytes(0x85, 0xc0);
        code.jump(0x84, failure);
        code.bytes(0x4c, 0x39, 0x74, 0x24, 0x28);
        code.jump(0x85, failure);

        code.bytes(0x48, 0x83, 0xc9, 0xff);
        code.bytes(0x4c, 0x89, 0xea);
        code.bytes(0x45, 0x89, 0xf0);             // r8d = r14d
        code.callRegister(3);
        code.bytes(0x85, 0xc0);
        code.jump(0x84, failure);
        code.bytes(0x41, 0xc6, 0x44, 0x24, 0x00, 1);
        code.jump(0xe9, done);
        code.bind(failure);
        code.bind(done);
        code.bytes(0x31, 0xc0);
        code.bytes(0x48, 0x83, 0xc4, 0x28);
        code.bytes(0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5b, 0x5d, 0xc3);
        code.bind(data);
        code.raw(replacement);
        return code.toByteArray();
    }

    private static final class Code {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream(512);
        private final List<Fixup> fixups = new ArrayList<Fixup>();

        void bytes(int... values) {
            for (int value : values) {
                output.write(value & 0xff);
            }
        }

        void raw(byte[] values) {
            for (byte value : values) {
                output.write(value & 0xff);
            }
        }

        void intValue(int value) {
            for (int i = 0; i < 4; i++) {
                output.write((value >>> (i * 8)) & 0xff);
            }
        }

        void longValue(long value) {
            for (int i = 0; i < 8; i++) {
                output.write((int) (value & 0xff));
                value >>>= 8;
            }
        }

        void call(long address) {
            bytes(0x49, 0xbb);
            longValue(address);
            bytes(0x41, 0xff, 0xd3);
        }

        void callRegister(int register) {
            if (register >= 8) {
                bytes(0x41);
            }
            bytes(0xff, 0xd0 + register % 8);
        }

        void loadAgent() {
            bytes(0x48, 0x8b, 0x4c, 0x24, 0x28);
        }

        void storeOutput(int displacement) {
            bytes(0x49, 0x89, 0x44, 0x24, displacement);
        }

        void status(int value) {
            bytes(0x49, 0xc7, 0x44, 0x24, 0x28);
            intValue(value);
        }

        void stackString(String value, int displacement) {
            for (int offset = 0; offset <= value.length(); offset += 8) {
                long chunk = 0;
                for (int i = 0; i < 8 && offset + i < value.length(); i++) {
                    char c = value.charAt(offset + i);
                    if (c > 0x7f) {
                        throw new IllegalArgumentException("Native string must be ASCII");
                    }
                    chunk |= (long) c << (i * 8);
                }
                bytes(0x48, 0xb8);
                longValue(chunk);
                bytes(0x48, 0x89, 0x44, 0x24, displacement + offset);
            }
        }

        void ripLea(int register, Label label) {
            int rex = 0x48 | (register >= 8 ? 4 : 0);
            bytes(rex, 0x8d, (register % 8) << 3 | 5);
            int operand = output.size();
            bytes(0, 0, 0, 0);
            fixups.add(new Fixup(label, operand));
        }

        void jump(int condition, Label label) {
            if (condition == 0xe9) {
                bytes(0xe9);
            } else {
                bytes(0x0f, condition);
            }
            int operand = output.size();
            bytes(0, 0, 0, 0);
            fixups.add(new Fixup(label, operand));
        }

        void bind(Label label) {
            if (label.position >= 0) {
                throw new IllegalStateException("Native stub label was bound twice");
            }
            label.position = output.size();
        }

        byte[] toByteArray() {
            byte[] bytes = output.toByteArray();
            for (Fixup fixup : fixups) {
                if (fixup.label.position < 0) {
                    throw new IllegalStateException("Unbound native stub label");
                }
                int relative = fixup.label.position - (fixup.operand + 4);
                for (int i = 0; i < 4; i++) {
                    bytes[fixup.operand + i] = (byte) (relative >>> (i * 8));
                }
            }
            if (bytes.length > 1000) {
                throw new IllegalArgumentException("Windows attach stub exceeds the JDK enqueue buffer");
            }
            return bytes;
        }
    }

    private static final class Label {
        private int position = -1;
    }

    private static final class Fixup {
        private final Label label;
        private final int operand;

        private Fixup(Label label, int operand) {
            this.label = label;
            this.operand = operand;
        }
    }
}
