package com.reajason.javaweb.fileless;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/** Builds the live-phase JPLIS initialization sequence for AArch64. */
final class AArch64NativeStub {
    private static final int SP = 31;
    private static final int VM_SLOT = 48;
    private static final int AGENT_SLOT = 56;
    private static final int VM_COUNT_SLOT = 64;

    private AArch64NativeStub() {
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

        code.word(0xa9ba7bfd);                    // stp x29, x30, [sp, #-96]!
        code.word(0x910003fd);                    // mov x29, sp
        code.word(0xa90153f3);                    // stp x19, x20, [sp, #16]
        code.word(0xa9025bf5);                    // stp x21, x22, [sp, #32]
        code.mov64(19, 0);                        // JNIEnv
        code.mov64(20, 1);                        // receiver class

        code.add64(0, SP, VM_SLOT);
        code.movz32(1, 1);
        code.add64(2, SP, VM_COUNT_SLOT);
        code.call(jniGetCreatedJavaVMs);
        code.cbnz32(0, failure);
        code.ldr32(3, SP, VM_COUNT_SLOT);
        code.cmp32(3, 1);
        code.branchCond(0x0b, failure);       // lt

        code.ldr64(0, SP, VM_SLOT);
        code.add64(1, SP, AGENT_SLOT);
        code.call(createNewJPLISAgent);
        code.cbnz32(0, failure);
        code.ldr64(21, SP, AGENT_SLOT);

        code.mov64(0, 21);
        code.call(addRedefineClassesCapability);
        code.mov64(0, 21);
        code.call(retransformableEnvironment);
        code.cbz64(0, failure);

        if (printWarningOffset >= 0) {
            code.strb(31, 21, printWarningOffset);
        }
        code.mov64(0, 19);
        code.mov64(1, 21);
        code.call(createInstrumentationImpl);
        code.cbz32(0, failure);

        code.mov64(0, 21);
        code.call(setLivePhaseEventHandlers);
        code.cbz32(0, failure);
        code.ldr64(0, 21, instrumentationImplOffset);
        code.branch(done);

        code.bind(failure);
        code.movz64(0, 0);                        // null on failure

        code.bind(done);
        code.word(0xa9425bf5);                    // ldp x21, x22, [sp, #32]
        code.word(0xa94153f3);                    // ldp x19, x20, [sp, #16]
        code.word(0xa8c67bfd);                    // ldp x29, x30, [sp], #96
        code.word(0xd65f03c0);                    // ret
        return code.toByteArray();
    }

    private static int scaledOffset(int offset, int scale) {
        if (offset < 0 || offset % scale != 0 || offset / scale > 4095) {
            throw new IllegalArgumentException("Invalid AArch64 scaled offset");
        }
        return (offset / scale) << 10;
    }

    private static final class Code {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream(384);
        private final List<Fixup> fixups = new ArrayList<Fixup>();

        void word(int value) {
            output.write(value & 0xff);
            output.write((value >>> 8) & 0xff);
            output.write((value >>> 16) & 0xff);
            output.write((value >>> 24) & 0xff);
        }

        void mov64(int destination, int source) {
            word(0xaa0003e0 | source << 16 | destination);
        }

        void movz32(int destination, int immediate) {
            word(0x52800000 | (immediate & 0xffff) << 5 | destination);
        }

        void movz64(int destination, int immediate) {
            word(0xd2800000 | (immediate & 0xffff) << 5 | destination);
        }

        void movk64(int destination, int immediate, int shift) {
            word(0xf2800000 | (shift / 16) << 21 | (immediate & 0xffff) << 5 | destination);
        }

        void add64(int destination, int base, int immediate) {
            if (immediate < 0 || immediate > 4095) {
                throw new IllegalArgumentException("Invalid AArch64 immediate");
            }
            word(0x91000000 | immediate << 10 | base << 5 | destination);
        }

        void cmp32(int base, int immediate) {
            if (immediate < 0 || immediate > 4095) {
                throw new IllegalArgumentException("Invalid AArch64 immediate");
            }
            word(0x7100001f | immediate << 10 | base << 5);
        }

        void ldr64(int destination, int base, int offset) {
            word(0xf9400000 | scaledOffset(offset, 8) | base << 5 | destination);
        }

        void ldr32(int destination, int base, int offset) {
            word(0xb9400000 | scaledOffset(offset, 4) | base << 5 | destination);
        }

        void str32(int source, int base, int offset) {
            word(0xb9000000 | scaledOffset(offset, 4) | base << 5 | source);
        }

        void strb(int source, int base, int offset) {
            word(0x39000000 | scaledOffset(offset, 1) | base << 5 | source);
        }

        void call(long address) {
            movz64(16, (int) address);
            movk64(16, (int) (address >>> 16), 16);
            movk64(16, (int) (address >>> 32), 32);
            movk64(16, (int) (address >>> 48), 48);
            blr(16);
        }

        void blr(int target) {
            word(0xd63f0000 | target << 5);
        }

        void branch(Label label) {
            fixup(0x14000000, label, 26);
        }

        void branchCond(int condition, Label label) {
            fixup(0x54000000 | condition, label, 19);
        }

        void cbz32(int register, Label label) {
            fixup(0x34000000 | register, label, 19);
        }

        void cbnz32(int register, Label label) {
            fixup(0x35000000 | register, label, 19);
        }

        void cbz64(int register, Label label) {
            fixup(0xb4000000 | register, label, 19);
        }

        private void fixup(int instruction, Label label, int immediateBits) {
            int position = output.size();
            word(instruction);
            fixups.add(new Fixup(position, instruction, label, immediateBits));
        }

        void bind(Label label) {
            if (label.position >= 0) {
                throw new IllegalStateException("Duplicate native stub label");
            }
            label.position = output.size();
        }

        byte[] toByteArray() {
            byte[] bytes = output.toByteArray();
            for (Fixup fixup : fixups) {
                if (fixup.label.position < 0) {
                    throw new IllegalStateException("Unbound native stub label");
                }
                int relative = (fixup.label.position - fixup.position) / 4;
                int limit = 1 << (fixup.immediateBits - 1);
                if (relative < -limit || relative >= limit) {
                    throw new IllegalStateException("AArch64 branch exceeds its immediate range");
                }
                int instruction = fixup.instruction;
                if (fixup.immediateBits == 26) {
                    instruction |= relative & 0x03ffffff;
                } else {
                    instruction |= (relative & 0x0007ffff) << 5;
                }
                for (int i = 0; i < 4; i++) {
                    bytes[fixup.position + i] = (byte) (instruction >>> (i * 8));
                }
            }
            return bytes;
        }
    }

    private static final class Label {
        private int position = -1;
    }

    private static final class Fixup {
        private final int position;
        private final int instruction;
        private final Label label;
        private final int immediateBits;

        private Fixup(int position, int instruction, Label label, int immediateBits) {
            this.position = position;
            this.instruction = instruction;
            this.label = label;
            this.immediateBits = immediateBits;
        }
    }
}
