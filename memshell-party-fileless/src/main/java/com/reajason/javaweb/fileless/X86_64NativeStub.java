package com.reajason.javaweb.fileless;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/** Builds the live-phase JPLIS initialization sequence for System V AMD64. */
final class X86_64NativeStub {
    private X86_64NativeStub() {
    }

    static byte[] acquireInstrumentation(long jniGetCreatedJavaVMs,
                                         long createNewJPLISAgent,
                                         long addRedefineClassesCapability,
                                         long retransformableEnvironment,
                                         long createInstrumentationImpl,
                                         long setLivePhaseEventHandlers,
                                         int instrumentationImplOffset) {
        return acquireInstrumentation(jniGetCreatedJavaVMs, createNewJPLISAgent,
                addRedefineClassesCapability, retransformableEnvironment, createInstrumentationImpl,
                setLivePhaseEventHandlers, instrumentationImplOffset, -1);
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

        code.bytes(0x55);                         // push rbp
        code.bytes(0x48, 0x89, 0xe5);             // mov rbp, rsp
        code.bytes(0x41, 0x54);                   // push r12
        code.bytes(0x41, 0x55);                   // push r13
        code.bytes(0x53);                         // push rbx
        code.bytes(0x48, 0x83, 0xec, 0x28);       // sub rsp, 40 (call-aligned)
        code.bytes(0x49, 0x89, 0xfc);             // mov r12, rdi (JNIEnv)
        code.bytes(0x49, 0x89, 0xf5);             // mov r13, rsi (jclass receiver)

        code.bytes(0x48, 0x89, 0xe7);             // mov rdi, rsp (JavaVM **)
        code.bytes(0xbe, 0x01, 0, 0, 0);          // mov esi, 1
        code.bytes(0x48, 0x8d, 0x54, 0x24, 0x10); // lea rdx, [rsp + 16]
        code.call(jniGetCreatedJavaVMs);
        code.bytes(0x85, 0xc0);                   // test eax, eax
        code.jump(0x85, failure);             // jne failure
        code.bytes(0x83, 0x7c, 0x24, 0x10, 0x01); // cmp dword [rsp + 16], 1
        code.jump(0x8c, failure);             // jl failure

        code.bytes(0x48, 0x8b, 0x3c, 0x24);       // mov rdi, [rsp] (JavaVM)
        code.bytes(0x48, 0x8d, 0x74, 0x24, 0x08); // lea rsi, [rsp + 8] (agent **)
        code.call(createNewJPLISAgent);
        code.bytes(0x85, 0xc0);
        code.jump(0x85, failure);

        code.loadAgentIntoRdi();
        code.call(addRedefineClassesCapability);

        code.loadAgentIntoRdi();
        code.call(retransformableEnvironment);
        code.bytes(0x48, 0x85, 0xc0);             // test rax, rax (jvmtiEnv *)
        code.jump(0x84, failure);             // je failure

        if (printWarningOffset >= 0) {
            code.bytes(0x48, 0x8b, 0x44, 0x24, 0x08); // mov rax, [rsp + 8] (agent)
            code.bytes(0xc6, 0x40, printWarningOffset, 0); // no dynamic agent JAR to report
        }

        code.bytes(0x4c, 0x89, 0xe7);             // mov rdi, r12 (JNIEnv)
        code.bytes(0x48, 0x8b, 0x74, 0x24, 0x08); // mov rsi, [rsp + 8] (agent)
        code.call(createInstrumentationImpl);
        code.bytes(0x84, 0xc0);                   // test al, al
        code.jump(0x84, failure);

        code.loadAgentIntoRdi();
        code.call(setLivePhaseEventHandlers);
        code.bytes(0x84, 0xc0);
        code.jump(0x84, failure);

        code.bytes(0x48, 0x8b, 0x44, 0x24, 0x08); // mov rax, [rsp + 8]
        code.bytes(0x48, 0x8b, 0x40, instrumentationImplOffset); // return agent->mInstrumentationImpl
        code.bytes(0x48, 0x85, 0xc0);             // test rax, rax
        code.jump(0x84, failure);             // je failure
        code.jump(0xe9, done);

        code.bind(failure);
        code.bytes(0x31, 0xc0);                   // xor eax, eax (null on failure)

        code.bind(done);
        code.bytes(0x48, 0x83, 0xc4, 0x28);       // add rsp, 40
        code.bytes(0x5b);                         // pop rbx
        code.bytes(0x41, 0x5d);                   // pop r13
        code.bytes(0x41, 0x5c);                   // pop r12
        code.bytes(0x5d);                         // pop rbp
        code.bytes(0xc3);                         // ret
        return code.toByteArray();
    }

    private static final class Code {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream(256);
        private final List<Fixup> fixups = new ArrayList<Fixup>();

        void bytes(int... values) {
            for (int value : values) {
                output.write(value & 0xff);
            }
        }

        void call(long address) {
            bytes(0x49, 0xbb); // movabs r11, address
            long value = address;
            for (int i = 0; i < 8; i++) {
                output.write((int) (value & 0xff));
                value >>>= 8;
            }
            bytes(0x41, 0xff, 0xd3); // call r11
        }

        void loadAgentIntoRdi() {
            bytes(0x48, 0x8b, 0x7c, 0x24, 0x08); // mov rdi, [rsp + 8]
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
