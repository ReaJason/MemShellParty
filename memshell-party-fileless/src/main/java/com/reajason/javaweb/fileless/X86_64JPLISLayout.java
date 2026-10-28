package com.reajason.javaweb.fileless;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/** Recover the JPLIS fields used by the native stub from compiler-generated x86-64 code. */
final class X86_64JPLISLayout {
    private static final int RAX = 0;
    private static final int RSI = 6;
    private static final int RDI = 7;
    private static final int R8 = 8;
    private static final int MAX_INSTRUCTIONS = 65536;

    private X86_64JPLISLayout() {
    }

    static Layout analyze(byte[] createInstrumentationImpl, byte[] initializeJPLISAgent,
                          boolean warningRequired) {
        if (createInstrumentationImpl == null || createInstrumentationImpl.length == 0) {
            throw invalid("Missing createInstrumentationImpl code");
        }
        List<Instruction> code = decode(createInstrumentationImpl);
        Candidate candidate = instrumentationField(code);
        int warning = warningRequired
                ? warningField(code, candidate, initializeJPLISAgent) : -1;
        return new Layout(candidate.displacement, warning);
    }

    private static Candidate instrumentationField(List<Instruction> code) {
        Map<Integer, TreeSet<Integer>> stores = new TreeMap<Integer, TreeSet<Integer>>();
        for (int i = 0; i < code.size(); i++) {
            Instruction instruction = code.get(i);
            if (instruction.opcode != 0x89 || !instruction.rexW || !instruction.simpleMemory
                    || !isCandidateBase(instruction.base) || instruction.displacement < 0
                    || instruction.displacement > 127) {
                continue;
            }
            TreeSet<Integer> displacements = stores.get(instruction.base);
            if (displacements == null) {
                displacements = new TreeSet<Integer>();
                stores.put(instruction.base, displacements);
            }
            displacements.add(instruction.displacement);
        }
        Candidate result = null;
        for (Map.Entry<Integer, TreeSet<Integer>> entry : stores.entrySet()) {
            TreeSet<Integer> displacements = entry.getValue();
            for (Integer displacement : displacements) {
                int value = displacement.intValue();
                if ((value & 7) != 0 || value > 103
                        || !displacements.contains(value + 8)
                        || !displacements.contains(value + 16)
                        || !displacements.contains(value + 24)) {
                    continue;
                }
                if (result != null) {
                    throw invalid("Ambiguous JPLIS InstrumentationImpl field candidates");
                }
                result = new Candidate(entry.getKey().intValue(), value);
            }
        }
        if (result == null) {
            throw invalid("Could not identify the four JPLIS object fields");
        }
        requireAgentProvenance(code, result);
        return result;
    }

    private static void requireAgentProvenance(List<Instruction> code, Candidate candidate) {
        State[] states = propagateAgent(code);
        int reachableStores = 0;
        for (int i = 0; i < code.size(); i++) {
            if (!isFieldStore(code.get(i), candidate) || states[i] == null) {
                continue;
            }
            reachableStores++;
            if (!states[i].registers[candidate.base]) {
                throw invalid("JPLIS field base is not the incoming agent on every path");
            }
        }
        if (reachableStores == 0) {
            throw invalid("JPLIS object stores are unreachable");
        }
    }

    private static State[] propagateAgent(List<Instruction> code) {
        Map<Integer, Integer> byOffset = new TreeMap<Integer, Integer>();
        for (int i = 0; i < code.size(); i++) {
            byOffset.put(Integer.valueOf(code.get(i).offset), Integer.valueOf(i));
        }
        State[] states = new State[code.size()];
        List<Integer> pending = new ArrayList<Integer>();
        boolean[] queued = new boolean[code.size()];
        State entry = new State();
        entry.registers[RSI] = true;
        states[0] = entry;
        pending.add(Integer.valueOf(0));
        queued[0] = true;
        int visits = 0;
        for (int cursor = 0; cursor < pending.size(); cursor++) {
            if (++visits > MAX_INSTRUCTIONS * 4) {
                throw invalid("JPLIS provenance analysis exceeds the state limit");
            }
            int index = pending.get(cursor).intValue();
            queued[index] = false;
            Instruction instruction = code.get(index);
            if (instruction.opcode == 0xff && instruction.reg == 4) {
                throw invalid("Indirect jump in JPLIS provenance analysis");
            }
            if (isReturn(instruction)) {
                continue;
            }
            State next = transfer(instruction, states[index]);
            if (instruction.opcode == 0xe9 || instruction.opcode == 0xeb) {
                mergeAgentState(code, states, pending, queued,
                        branchTarget(code, byOffset, instruction), next);
            } else {
                if (isConditionalBranch(instruction)) {
                    mergeAgentState(code, states, pending, queued,
                            branchTarget(code, byOffset, instruction), next);
                }
                mergeAgentState(code, states, pending, queued, index + 1, next);
            }
        }
        return states;
    }

    private static int branchTarget(List<Instruction> code, Map<Integer, Integer> byOffset,
                                    Instruction instruction) {
        Integer target = byOffset.get(Integer.valueOf((int) instruction.branchTarget));
        if (target == null) {
            throw invalid("JPLIS branch does not target an instruction boundary");
        }
        return target.intValue();
    }

    private static void mergeAgentState(List<Instruction> code, State[] states,
                                        List<Integer> pending, boolean[] queued,
                                        int target, State incoming) {
        if (target == code.size()) {
            return;
        }
        if (target < 0 || target > code.size()) {
            throw invalid("Invalid JPLIS control-flow successor");
        }
        boolean changed;
        if (states[target] == null) {
            states[target] = incoming.copy();
            changed = true;
        } else {
            changed = states[target].intersect(incoming);
        }
        if (changed && !queued[target]) {
            pending.add(Integer.valueOf(target));
            queued[target] = true;
        }
    }

    private static State transfer(Instruction instruction, State input) {
        State result = input.copy();
        if (instruction.isCall()) {
            for (int register = 0; register < result.registers.length; register++) {
                if (!isCalleeSaved(register) && register != 4 && register != 5) {
                    result.registers[register] = false;
                }
            }
            return result;
        }
        if (instruction.memory && instruction.base == 5) {
            if (instruction.simpleMemory && instruction.opcode == 0x89 && instruction.rexW) {
                if (instruction.sourceRegister >= 0 && input.registers[instruction.sourceRegister]) {
                    result.agentSpills.add(Integer.valueOf(instruction.displacement));
                } else {
                    result.agentSpills.remove(Integer.valueOf(instruction.displacement));
                }
            } else if (!isReadOnlyMemory(instruction)) {
                if (instruction.simpleMemory) {
                    result.agentSpills.remove(Integer.valueOf(instruction.displacement));
                } else {
                    result.agentSpills.clear();
                }
            }
        }
        if ((instruction.opcode == 0x89 || instruction.opcode == 0x8b)
                && instruction.rexW && !instruction.memory
                && instruction.destinationRegister >= 0 && instruction.sourceRegister >= 0) {
            result.registers[instruction.destinationRegister]
                    = input.registers[instruction.sourceRegister];
        } else if (instruction.opcode == 0x8b && instruction.rexW
                && instruction.destinationRegister >= 0) {
            result.registers[instruction.destinationRegister] = instruction.simpleMemory
                    && instruction.base == 5
                    && input.agentSpills.contains(Integer.valueOf(instruction.displacement));
        } else if (instruction.destinationRegister >= 0
                && (instruction.opcode < 0x50 || instruction.opcode > 0x57)) {
            result.registers[instruction.destinationRegister] = false;
        } else if (!isRegisterPreserving(instruction)) {
            for (int register = 0; register < result.registers.length; register++) {
                result.registers[register] = false;
            }
            result.agentSpills.clear();
        }
        if (instruction.destinationRegister == 5 || instruction.opcode == 0xc9) {
            result.registers[5] = false;
            result.agentSpills.clear();
        }
        return result;
    }

    private static boolean isRegisterPreserving(Instruction instruction) {
        int opcode = instruction.opcode;
        return instruction.isBranch() || isReturn(instruction) || opcode == 0x90
                || opcode >= 0x50 && opcode <= 0x57 || opcode == 0x0f1f || opcode == 0xc9 || opcode == 0x68 || opcode == 0x6a
                || opcode == 0x9c || opcode == 0x9d || opcode == 0x84 || opcode == 0x85
                || opcode >= 0x38 && opcode <= 0x3d
                || opcode >= 0x80 && opcode <= 0x83 && (instruction.memory || instruction.reg == 7)
                || (opcode == 0xf6 || opcode == 0xf7) && instruction.reg <= 1
                || opcode == 0xff && instruction.reg == 6
                || instruction.memory && (opcode == 0x88 || opcode == 0x89
                || opcode == 0xc6 || opcode == 0xc7
                || opcode >= 0xc0 && opcode <= 0xc1 || opcode >= 0xd0 && opcode <= 0xd3
                || opcode >= 0x0f90 && opcode <= 0x0f9f
                || opcode <= 0x31 && (opcode & 7) <= 1);
    }

    private static boolean isReadOnlyMemory(Instruction instruction) {
        int opcode = instruction.opcode;
        return opcode == 0x8a || opcode == 0x8b || opcode == 0x8d
                || opcode >= 0x38 && opcode <= 0x3d || opcode == 0x84 || opcode == 0x85
                || opcode == 0x0fb6 || opcode == 0x0fb7 || opcode == 0x0fbe || opcode == 0x0fbf
                || opcode == 0x0f1f || opcode >= 0x80 && opcode <= 0x83 && instruction.reg == 7
                || (opcode == 0xf6 || opcode == 0xf7) && instruction.reg <= 1
                || opcode == 0xff && (instruction.reg == 2 || instruction.reg == 4
                || instruction.reg == 6);
    }

    private static boolean isReturn(Instruction instruction) {
        return instruction.opcode == 0xc3 || instruction.opcode == 0xc2
                || instruction.opcode == 0xca || instruction.opcode == 0xcb;
    }

    private static boolean isConditionalBranch(Instruction instruction) {
        return instruction.opcode >= 0x70 && instruction.opcode <= 0x7f
                || instruction.opcode >= 0x0f80 && instruction.opcode <= 0x0f8f;
    }

    private static boolean isFieldStore(Instruction instruction, Candidate candidate) {
        return instruction.opcode == 0x89 && instruction.rexW && instruction.simpleMemory
                && instruction.base == candidate.base
                && instruction.displacement >= candidate.displacement
                && instruction.displacement <= candidate.displacement + 24;
    }

    private static boolean isCandidateBase(int register) {
        return register >= 0 && register != 4 && register != 5;
    }

    private static int warningField(List<Instruction> code, Candidate candidate,
                                    byte[] initializeJPLISAgent) {
        if (initializeJPLISAgent == null || initializeJPLISAgent.length == 0) {
            throw invalid("Warning constructor requires initializeJPLISAgent code");
        }
        int result = -1;
        int newObjectCalls = 0;
        for (int i = 0; i < code.size(); i++) {
            Instruction call = code.get(i);
            if (call.opcode != 0xff || call.reg != 2 || !call.simpleMemory
                    || call.displacement != 0xe0) {
                continue;
            }
            newObjectCalls++;
            int displacement = warningArgument(code, i, candidate.base);
            if (displacement < 0 || (result != -1 && result != displacement)) {
                throw invalid("Ambiguous JPLIS warning constructor argument");
            }
            result = displacement;
        }
        if (newObjectCalls != 1 || result < 0 || result > 127
                || result >= candidate.displacement && result <= candidate.displacement + 24) {
            throw invalid("Could not identify the JPLIS warning field");
        }
        boolean initialized = false;
        List<Instruction> initialization = decode(initializeJPLISAgent);
        for (int i = 0; i < initialization.size(); i++) {
            Instruction instruction = initialization.get(i);
            if (instruction.opcode != 0x88 || !instruction.simpleMemory
                    || instruction.sourceRegister != R8 || instruction.displacement != result
                    || !isFirstArgument(initialization, i, instruction.base)) {
                continue;
            }
            if (initialized) {
                throw invalid("Ambiguous JPLIS warning-field initialization");
            }
            initialized = true;
        }
        if (!initialized) {
            throw invalid("JPLIS warning field is not corroborated by agent initialization");
        }
        return result;
    }

    private static int warningArgument(List<Instruction> code, int callIndex, int agentBase) {
        int push = -1;
        for (int i = callIndex - 1; i >= 0 && callIndex - i <= 20; i--) {
            Instruction instruction = code.get(i);
            if (instruction.isCall()) {
                break;
            }
            if (instruction.opcode == 0x50 && instruction.destinationRegister == RAX) {
                push = i;
                break;
            }
        }
        if (push < 0) {
            return -1;
        }
        for (int i = push - 1; i >= 0 && push - i <= 20; i--) {
            Instruction instruction = code.get(i);
            if (instruction.isCall()) {
                break;
            }
            if (instruction.destinationRegister == RAX) {
                if (instruction.opcode == 0x0fb6 && instruction.simpleMemory
                        && instruction.base == agentBase && instruction.displacement >= 0
                        && instruction.displacement <= 127) {
                    return instruction.displacement;
                }
                return -1;
            }
        }
        return -1;
    }

    private static boolean isFirstArgument(List<Instruction> code, int storeIndex, int base) {
        if (base == RDI) {
            return true;
        }
        for (int i = 0; i < storeIndex; i++) {
            Instruction instruction = code.get(i);
            if (instruction.opcode == 0x89 && instruction.rexW && !instruction.memory
                    && instruction.destinationRegister == base) {
                return instruction.sourceRegister == RDI;
            }
        }
        return false;
    }

    private static boolean isCalleeSaved(int register) {
        return register == 3 || register >= 12 && register <= 15;
    }

    private static List<Instruction> decode(byte[] bytes) {
        return decode(bytes, false);
    }

    private static List<Instruction> decode(byte[] bytes, boolean allowExternalBranches) {
        List<Instruction> result = new ArrayList<Instruction>();
        int offset = 0;
        while (offset < bytes.length) {
            if (result.size() >= MAX_INSTRUCTIONS) {
                throw invalid("Native function exceeds the instruction limit");
            }
            Instruction instruction = Instruction.decode(bytes, offset);
            if (!allowExternalBranches && instruction.isBranch() && instruction.opcode != 0xe8
                    && (instruction.branchTarget < 0 || instruction.branchTarget >= bytes.length)) {
                throw invalid("Native branch escapes the resolved function at 0x"
                        + Integer.toHexString(instruction.offset) + ", opcode="
                        + Integer.toHexString(instruction.opcode) + ", target="
                        + instruction.branchTarget);
            }
            result.add(instruction);
            offset += instruction.length;
        }
        return result;
    }

    static Call[] directCalls(byte[] code, long virtualAddress) {
        List<Instruction> instructions = decode(code, true);
        List<Call> result = new ArrayList<Call>();
        for (int i = 0; i < instructions.size(); i++) {
            Instruction instruction = instructions.get(i);
            if (instruction.opcode == 0xe8) {
                result.add(new Call(instruction.offset,
                        virtualAddress + instruction.branchTarget));
            }
        }
        return result.toArray(new Call[result.size()]);
    }

    static Call[] directCallsAndTailJumps(byte[] code, long virtualAddress) {
        List<Instruction> instructions = decode(code, true);
        List<Call> result = new ArrayList<Call>();
        for (int i = 0; i < instructions.size(); i++) {
            Instruction instruction = instructions.get(i);
            if (instruction.opcode == 0xe8 || instruction.opcode == 0xe9
                    && (instruction.branchTarget < 0 || instruction.branchTarget >= code.length)) {
                result.add(new Call(instruction.offset,
                        virtualAddress + instruction.branchTarget));
            }
        }
        return result.toArray(new Call[result.size()]);
    }

    static long directTailJump(byte[] wrapper, long virtualAddress) {
        List<Instruction> instructions = decode(wrapper, true);
        long result = Long.MIN_VALUE;
        for (int i = 0; i < instructions.size(); i++) {
            Instruction instruction = instructions.get(i);
            if (instruction.opcode == 0xe9) {
                if (result != Long.MIN_VALUE) {
                    throw invalid("Ambiguous JNI tail jumps");
                }
                result = virtualAddress + instruction.branchTarget;
            }
        }
        if (result == Long.MIN_VALUE) {
            throw invalid("JNI wrapper has no direct tail jump");
        }
        return result;
    }

    static boolean hasIndirectCall(byte[] code, int displacement) {
        List<Instruction> instructions = decode(code, true);
        for (int i = 0; i < instructions.size(); i++) {
            Instruction instruction = instructions.get(i);
            if (instruction.opcode == 0xff && instruction.reg == 2
                    && instruction.simpleMemory && instruction.displacement == displacement) {
                return true;
            }
        }
        return false;
    }

    static boolean hasOrImmediate(byte[] code, int immediate) {
        List<Instruction> instructions = decode(code, true);
        for (int i = 0; i < instructions.size(); i++) {
            Instruction instruction = instructions.get(i);
            if ((instruction.opcode == 0x80 || instruction.opcode == 0x81
                    || instruction.opcode == 0x83) && instruction.reg == 1
                    && instruction.memory && instruction.immediate == immediate) {
                return true;
            }
        }
        return false;
    }

    private static UnsupportedOperationException invalid(String message) {
        return new UnsupportedOperationException(message + "; native state was not changed");
    }

    static final class Call {
        final int offset;
        final long target;

        Call(int offset, long target) {
            this.offset = offset;
            this.target = target;
        }
    }

    static final class Layout {
        final int instrumentationImplOffset;
        final int printWarningOffset;

        Layout(int instrumentationImplOffset, int printWarningOffset) {
            this.instrumentationImplOffset = instrumentationImplOffset;
            this.printWarningOffset = printWarningOffset;
        }
    }

    private static final class Candidate {
        private final int base;
        private final int displacement;

        private Candidate(int base, int displacement) {
            this.base = base;
            this.displacement = displacement;
        }
    }

    private static final class State {
        private final boolean[] registers = new boolean[16];
        private final TreeSet<Integer> agentSpills = new TreeSet<Integer>();

        private State copy() {
            State result = new State();
            System.arraycopy(registers, 0, result.registers, 0, registers.length);
            result.agentSpills.addAll(agentSpills);
            return result;
        }

        private boolean intersect(State other) {
            boolean changed = false;
            for (int i = 0; i < registers.length; i++) {
                if (registers[i] && !other.registers[i]) {
                    registers[i] = false;
                    changed = true;
                }
            }
            return agentSpills.retainAll(other.agentSpills) || changed;
        }
    }

    private static final class Instruction {
        private int offset;
        private int length;
        private int opcode;
        private boolean rexW;
        private int reg = -1;
        private int base = -1;
        private boolean memory;
        private boolean simpleMemory;
        private int displacement;
        private int destinationRegister = -1;
        private int sourceRegister = -1;
        private long branchTarget = Long.MIN_VALUE;
        private long immediate;

        private boolean isCall() {
            return opcode == 0xe8 || opcode == 0xff && reg == 2;
        }

        private boolean isBranch() {
            return opcode == 0xe8 || opcode == 0xe9 || opcode == 0xeb
                    || opcode >= 0x70 && opcode <= 0x7f
                    || opcode >= 0x0f80 && opcode <= 0x0f8f;
        }

        private static Instruction decode(byte[] bytes, int start) {
            Instruction result = new Instruction();
            result.offset = start;
            int cursor = start;
            boolean operand16 = false;
            int rex = 0;
            while (cursor < bytes.length) {
                int value = bytes[cursor] & 0xff;
                if (value == 0x66) {
                    operand16 = true;
                } else if (!(value == 0xf0 || value == 0xf2 || value == 0xf3
                        || value == 0x2e || value == 0x36 || value == 0x3e
                        || value == 0x26 || value == 0x64 || value == 0x65 || value == 0x67)
                        && (value < 0x40 || value > 0x4f)) {
                    break;
                }
                if (value >= 0x40 && value <= 0x4f) {
                    rex = value;
                }
                cursor++;
                if (cursor - start >= 15) {
                    throw invalid("Oversized x86-64 instruction");
                }
            }
            if (cursor >= bytes.length) {
                throw invalid("Truncated x86-64 instruction");
            }
            result.rexW = (rex & 8) != 0;
            int first = bytes[cursor++] & 0xff;
            int opcode = first;
            if (first == 0xc4 || first == 0xc5 || first == 0x62) {
                throw invalid("Unsupported VEX/EVEX instruction in JPLIS analysis");
            }
            if (first == 0x0f) {
                if (cursor >= bytes.length) {
                    throw invalid("Truncated x86-64 opcode");
                }
                int second = bytes[cursor++] & 0xff;
                opcode = 0x0f00 | second;
                if (second == 0x38 || second == 0x3a) {
                    if (cursor >= bytes.length) {
                        throw invalid("Truncated three-byte x86-64 opcode");
                    }
                    opcode = 0x0f0000 | second << 8 | (bytes[cursor++] & 0xff);
                }
            }
            result.opcode = opcode;
            boolean hasModRM = hasModRM(opcode);
            int mod = 3;
            int rm = -1;
            if (hasModRM) {
                if (cursor >= bytes.length) {
                    throw invalid("Truncated x86-64 ModRM");
                }
                int modrm = bytes[cursor++] & 0xff;
                mod = modrm >>> 6;
                result.reg = ((modrm >>> 3) & 7) + ((rex & 4) != 0 ? 8 : 0);
                rm = (modrm & 7) + ((rex & 1) != 0 ? 8 : 0);
                result.memory = mod != 3;
                if (mod != 3) {
                    int baseRm = modrm & 7;
                    if (baseRm == 4) {
                        if (cursor >= bytes.length) {
                            throw invalid("Truncated x86-64 SIB");
                        }
                        int sib = bytes[cursor++] & 0xff;
                        int sibBase = sib & 7;
                        int index = (sib >>> 3) & 7;
                        if (sibBase != 5 || mod != 0) {
                            result.base = sibBase + ((rex & 1) != 0 ? 8 : 0);
                            result.simpleMemory = index == 4 && (rex & 2) == 0;
                        }
                    } else if (baseRm != 5 || mod != 0) {
                        result.base = rm;
                        result.simpleMemory = true;
                    }
                    if (baseRm == 4 && (bytes[cursor - 1] & 7) == 5 && mod == 0) {
                        cursor = readDisplacement(bytes, cursor, 4, result);
                    } else if (baseRm == 5 && mod == 0) {
                        cursor = readDisplacement(bytes, cursor, 4, result);
                    } else if (mod == 1) {
                        cursor = readDisplacement(bytes, cursor, 1, result);
                    } else if (mod == 2) {
                        cursor = readDisplacement(bytes, cursor, 4, result);
                    }
                }
            }
            if (opcode >= 0x50 && opcode <= 0x5f) {
                result.destinationRegister = (opcode & 7) + ((rex & 1) != 0 ? 8 : 0);
            } else if (opcode == 0x89 || opcode == 0x88) {
                result.sourceRegister = result.reg;
                if (mod == 3) {
                    result.destinationRegister = rm;
                }
            } else if (opcode == 0x8b || opcode == 0x8a || opcode == 0x0fb6 || opcode == 0x0fb7
                    || opcode == 0x0fbe || opcode == 0x0fbf || opcode == 0x63
                    || opcode == 0x69 || opcode == 0x6b || opcode == 0x8d || opcode == 0x0faf
                    || opcode >= 0x0f40 && opcode <= 0x0f4f || opcode == 0x0fb8
                    || opcode == 0x0fbc || opcode == 0x0fbd) {
                result.destinationRegister = result.reg;
                if (mod == 3 && (opcode == 0x8b || opcode == 0x8a || opcode == 0x0fb6
                        || opcode == 0x0fb7 || opcode == 0x0fbe || opcode == 0x0fbf)) {
                    result.sourceRegister = rm;
                }
            } else if (opcode >= 0xb0 && opcode <= 0xbf) {
                result.destinationRegister = (opcode & 7) + ((rex & 1) != 0 ? 8 : 0);
            } else if (opcode <= 0x35 && ((opcode & 7) == 4 || (opcode & 7) == 5)) {
                result.destinationRegister = RAX;
            } else if (hasModRM && opcode <= 0x33 && (opcode & 7) <= 3) {
                if ((opcode & 7) >= 2) {
                    result.destinationRegister = result.reg;
                } else if (mod == 3) {
                    result.destinationRegister = rm;
                }
            } else if (hasModRM && mod == 3 && (opcode >= 0x0f90 && opcode <= 0x0f9f
                    || opcode >= 0x80 && opcode <= 0x83 && result.reg != 7
                    || opcode >= 0xc0 && opcode <= 0xc1 || opcode >= 0xd0 && opcode <= 0xd3
                    || (opcode == 0xfe || opcode == 0xff) && result.reg <= 1
                    || (opcode == 0xf6 || opcode == 0xf7) && result.reg >= 2 && result.reg <= 3)) {
                result.destinationRegister = rm;
            }
            int immediateBytes = immediateBytes(opcode, result.rexW, operand16, result.reg);
            if (cursor + immediateBytes > bytes.length || cursor + immediateBytes - start > 15) {
                throw invalid("Truncated x86-64 immediate");
            }
            if (result.isBranch()) {
                long relative = signed(bytes, cursor, immediateBytes);
                result.branchTarget = cursor + immediateBytes + relative;
            }
            if (immediateBytes > 0) {
                result.immediate = signed(bytes, cursor, immediateBytes);
            }
            cursor += immediateBytes;
            result.length = cursor - start;
            if (result.length <= 0 || result.length > 15) {
                throw invalid("Invalid x86-64 instruction length");
            }
            return result;
        }

        private static int readDisplacement(byte[] bytes, int cursor, int size, Instruction result) {
            if (cursor + size > bytes.length) {
                throw invalid("Truncated x86-64 displacement");
            }
            result.displacement = (int) signed(bytes, cursor, size);
            return cursor + size;
        }

        private static long signed(byte[] bytes, int offset, int size) {
            if (size <= 0 || size > 8 || offset < 0 || offset + size > bytes.length) {
                throw invalid("Invalid signed x86-64 operand");
            }
            long result = 0;
            for (int i = 0; i < size; i++) {
                result |= (long) (bytes[offset + i] & 0xff) << (i * 8);
            }
            int bits = size * 8;
            if (bits < 64 && (result & (1L << (bits - 1))) != 0) {
                result -= 1L << bits;
            }
            return result;
        }

        private static boolean hasModRM(int opcode) {
            if (opcode <= 0x3f) {
                return (opcode & 7) <= 3;
            }
            if (opcode >= 0x80 && opcode <= 0x8f || opcode == 0x63 || opcode == 0x69
                    || opcode == 0x6b || opcode == 0xc0 || opcode == 0xc1
                    || opcode == 0xc6 || opcode == 0xc7 || opcode >= 0xd0 && opcode <= 0xd3
                    || opcode >= 0xd8 && opcode <= 0xdf || opcode == 0xf6 || opcode == 0xf7
                    || opcode == 0xfe || opcode == 0xff) {
                return true;
            }
            if (opcode < 0x0f00) {
                return false;
            }
            if (opcode >= 0x0f0000) {
                return true;
            }
            int second = opcode & 0xff;
            if (second <= 0x03 || second >= 0x10 && second <= 0x2f
                    || second >= 0x38 && second <= 0x3a || second >= 0x40 && second <= 0x76
                    || second >= 0x78 && second <= 0x7f || second >= 0x90 && second <= 0x9f
                    || second == 0xa3 || second >= 0xa4 && second <= 0xa7
                    || second >= 0xaa && second <= 0xaf || second >= 0xb0 && second <= 0xc7
                    || second >= 0xd0) {
                return true;
            }
            if (second == 0x05 || second == 0x06 || second == 0x07 || second == 0x08
                    || second == 0x09 || second == 0x0b || second >= 0x30 && second <= 0x37
                    || second == 0x77 || second >= 0x80 && second <= 0x8f
                    || second >= 0xa0 && second <= 0xa2 || second == 0xa8 || second == 0xa9
                    || second >= 0xc8 && second <= 0xcf) {
                return false;
            }
            throw invalid("Unsupported x86-64 opcode in JPLIS analysis: "
                    + Integer.toHexString(opcode));
        }

        private static int immediateBytes(int opcode, boolean rexW, boolean operand16, int reg) {
            int word = operand16 ? 2 : 4;
            if (opcode <= 0x3f) {
                int low = opcode & 7;
                return low == 4 ? 1 : low == 5 ? word : 0;
            }
            if (opcode == 0x68 || opcode == 0x69 || opcode == 0x81 || opcode == 0xa9
                    || opcode == 0xc7) {
                return word;
            }
            if (opcode == 0x6a || opcode == 0x6b || opcode >= 0x70 && opcode <= 0x7f
                    || opcode == 0x80 || opcode == 0x82 || opcode == 0x83 || opcode == 0xa8
                    || opcode == 0xc0 || opcode == 0xc1 || opcode == 0xc6 || opcode == 0xcd
                    || opcode == 0xd4 || opcode == 0xd5 || opcode >= 0xe0 && opcode <= 0xe7
                    || opcode == 0xeb) {
                return 1;
            }
            if (opcode >= 0xb0 && opcode <= 0xb7) {
                return 1;
            }
            if (opcode >= 0xb8 && opcode <= 0xbf) {
                return rexW ? 8 : word;
            }
            if (opcode == 0xc2 || opcode == 0xca) {
                return 2;
            }
            if (opcode == 0xc8) {
                return 3;
            }
            if (opcode == 0xe8 || opcode == 0xe9) {
                return 4;
            }
            if (opcode == 0xf6) {
                return reg <= 1 ? 1 : 0;
            }
            if (opcode == 0xf7) {
                return reg <= 1 ? word : 0;
            }
            if (opcode >= 0x0f80 && opcode <= 0x0f8f) {
                return 4;
            }
            if (opcode >= 0x0f70 && opcode <= 0x0f76 || opcode == 0x0fa4 || opcode == 0x0fac
                    || opcode == 0x0fba || opcode == 0x0fc2 || opcode == 0x0fc4
                    || opcode == 0x0fc5 || opcode == 0x0fc6 || opcode >= 0x0f3a00) {
                return 1;
            }
            return 0;
        }
    }
}
