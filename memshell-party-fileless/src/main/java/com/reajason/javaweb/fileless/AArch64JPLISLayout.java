package com.reajason.javaweb.fileless;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/** Recover JPLIS field offsets from bounded AArch64 control flow and register provenance. */
final class AArch64JPLISLayout {
    private static final int AGENT_ARGUMENT = 1;
    private static final int WARNING_ARGUMENT = 4;
    private static final int NEW_OBJECT_ARGUMENT = 6;
    private static final int MAX_INSTRUCTIONS = 65536;

    private AArch64JPLISLayout() {
    }

    static Layout analyze(byte[] createInstrumentationImpl, byte[] initializeJPLISAgent,
                          boolean warningRequired) {
        if (createInstrumentationImpl == null || createInstrumentationImpl.length == 0) {
            throw invalid("Missing createInstrumentationImpl code");
        }
        List<Instruction> code = decode(createInstrumentationImpl);
        State[] states = propagate(code, AGENT_ARGUMENT);
        Candidate candidate = instrumentationField(code, states);
        int warning = warningRequired
                ? warningField(code, states, candidate, initializeJPLISAgent) : -1;
        return new Layout(candidate.displacement, warning);
    }

    private static Candidate instrumentationField(List<Instruction> code, State[] states) {
        Map<Integer, TreeSet<Integer>> stores = new TreeMap<Integer, TreeSet<Integer>>();
        for (int i = 0; i < code.size(); i++) {
            Instruction instruction = code.get(i);
            if (isStr64(instruction.word)) {
                addStore(stores, base(instruction.word), unsignedOffset(instruction.word, 8));
            } else if (isStp64(instruction.word)) {
                int displacement = pairDisplacement(instruction.word);
                addStore(stores, base(instruction.word), displacement);
                addStore(stores, base(instruction.word), displacement + 8);
            }
        }
        Candidate result = null;
        for (Map.Entry<Integer, TreeSet<Integer>> entry : stores.entrySet()) {
            int base = entry.getKey().intValue();
            if (base < 0 || base >= 31) {
                continue;
            }
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
                    throw invalid("Ambiguous AArch64 JPLIS field candidates");
                }
                result = new Candidate(base, value);
            }
        }
        if (result == null) {
            throw invalid("Could not identify the four AArch64 JPLIS object fields");
        }
        int reachableStores = 0;
        for (int i = 0; i < code.size(); i++) {
            Instruction instruction = code.get(i);
            if (states[i] == null) {
                continue;
            }
            int count = fieldStoreCount(instruction.word, result);
            if (count == 0) {
                continue;
            }
            if (!states[i].registers[result.base]) {
                throw invalid("AArch64 JPLIS field base is not the incoming agent on every path");
            }
            reachableStores += count;
        }
        if (reachableStores != 4) {
            throw invalid("AArch64 JPLIS object stores are not all reachable");
        }
        return result;
    }

    private static void addStore(Map<Integer, TreeSet<Integer>> stores, int base, int displacement) {
        if (base < 0 || base >= 31 || displacement < 0 || displacement > 127) {
            return;
        }
        TreeSet<Integer> values = stores.get(Integer.valueOf(base));
        if (values == null) {
            values = new TreeSet<Integer>();
            stores.put(Integer.valueOf(base), values);
        }
        values.add(Integer.valueOf(displacement));
    }

    private static int fieldStoreCount(int word, Candidate candidate) {
        if (base(word) != candidate.base) {
            return 0;
        }
        if (isStr64(word)) {
            int displacement = unsignedOffset(word, 8);
            return displacement >= candidate.displacement
                    && displacement <= candidate.displacement + 24 ? 1 : 0;
        }
        if (isStp64(word)) {
            int displacement = pairDisplacement(word);
            return displacement >= candidate.displacement
                    && displacement + 8 <= candidate.displacement + 24 ? 2 : 0;
        }
        return 0;
    }

    private static State[] propagate(List<Instruction> code, int initialRegister) {
        State[] states = new State[code.size()];
        List<Integer> pending = new ArrayList<Integer>();
        boolean[] queued = new boolean[code.size()];
        State entry = new State();
        entry.registers[initialRegister] = true;
        states[0] = entry;
        pending.add(Integer.valueOf(0));
        queued[0] = true;
        int visits = 0;
        for (int cursor = 0; cursor < pending.size(); cursor++) {
            if (++visits > MAX_INSTRUCTIONS * 4) {
                throw invalid("AArch64 provenance analysis exceeds the state limit");
            }
            int index = pending.get(cursor).intValue();
            queued[index] = false;
            Instruction instruction = code.get(index);
            if (instruction.isIndirectJump()) {
                throw invalid("Indirect jump in AArch64 provenance analysis");
            }
            if (instruction.isReturn()) {
                continue;
            }
            State next = transfer(instruction, states[index]);
            if (instruction.isUnconditionalBranch()) {
                merge(code, states, pending, queued, instruction.branchTarget, next);
            } else {
                if (instruction.isConditionalBranch()) {
                    merge(code, states, pending, queued, instruction.branchTarget, next);
                }
                merge(code, states, pending, queued, index + 1, next);
            }
        }
        return states;
    }

    private static State transfer(Instruction instruction, State input) {
        State result = input.copy();
        if (instruction.isCall()) {
            for (int register = 0; register <= 18; register++) {
                result.registers[register] = false;
            }
            result.registers[30] = false;
            return result;
        }
        if (instruction.moveSource >= 0) {
            if (instruction.destination < 31) {
                result.registers[instruction.destination] = input.registers[instruction.moveSource];
            }
            return result;
        }
        if (!instruction.semanticsKnown) {
            for (int register = 0; register < result.registers.length; register++) {
                result.registers[register] = false;
            }
            return result;
        }
        if (instruction.destination >= 0 && instruction.destination < 31) {
            result.registers[instruction.destination] = false;
        }
        if (instruction.secondDestination >= 0 && instruction.secondDestination < 31) {
            result.registers[instruction.secondDestination] = false;
        }
        if (instruction.writeback >= 0 && instruction.writeback < 31) {
            result.registers[instruction.writeback] = false;
        }
        return result;
    }

    private static void merge(List<Instruction> code, State[] states, List<Integer> pending,
                              boolean[] queued, int target, State incoming) {
        if (target == code.size()) {
            return;
        }
        if (target < 0 || target > code.size()) {
            throw invalid("Invalid AArch64 control-flow successor");
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

    private static int warningField(List<Instruction> code, State[] states, Candidate candidate,
                                    byte[] initializeJPLISAgent) {
        if (initializeJPLISAgent == null || initializeJPLISAgent.length == 0) {
            throw invalid("Warning constructor requires initializeJPLISAgent code");
        }
        int result = -1;
        int constructorCalls = 0;
        for (int i = 0; i < code.size(); i++) {
            Instruction call = code.get(i);
            if (!call.isBlr() || !isNewObjectCall(code, i)) {
                continue;
            }
            constructorCalls++;
            int displacement = warningArgument(code, states, i, candidate.base);
            if (displacement < 0 || result != -1 && result != displacement) {
                throw invalid("Ambiguous AArch64 JPLIS warning constructor argument");
            }
            result = displacement;
        }
        if (constructorCalls != 1 || result < 0 || result > 127
                || result >= candidate.displacement && result <= candidate.displacement + 24) {
            throw invalid("Could not identify the AArch64 JPLIS warning field");
        }
        List<Instruction> initialization = decode(initializeJPLISAgent);
        State[] firstArgument = propagate(initialization, 0);
        State[] warningArgument = propagate(initialization, WARNING_ARGUMENT);
        boolean initialized = false;
        for (int i = 0; i < initialization.size(); i++) {
            int word = initialization.get(i).word;
            if (!isStrb(word) || unsignedOffset(word, 1) != result
                    || firstArgument[i] == null || warningArgument[i] == null) {
                continue;
            }
            int base = base(word);
            int source = word & 31;
            if (base >= 31 || source >= 31
                    || !firstArgument[i].registers[base] || !warningArgument[i].registers[source]) {
                continue;
            }
            if (initialized) {
                throw invalid("Ambiguous AArch64 warning-field initialization");
            }
            initialized = true;
        }
        if (!initialized) {
            throw invalid("AArch64 warning field is not corroborated by agent initialization");
        }
        return result;
    }

    private static boolean isNewObjectCall(List<Instruction> code, int callIndex) {
        int target = (code.get(callIndex).word >>> 5) & 31;
        for (int i = callIndex - 1; i >= 0 && callIndex - i <= 20; i--) {
            Instruction instruction = code.get(i);
            if (instruction.isCall()) {
                break;
            }
            if (writes(instruction, target)) {
                return isLdr64(instruction.word) && (instruction.word & 31) == target
                        && unsignedOffset(instruction.word, 8) == 224;
            }
            if (!instruction.semanticsKnown) {
                return false;
            }
        }
        return false;
    }

    private static int warningArgument(List<Instruction> code, State[] states,
                                       int callIndex, int agentBase) {
        int target = NEW_OBJECT_ARGUMENT;
        for (int i = callIndex - 1; i >= 0 && callIndex - i <= 20; i--) {
            Instruction instruction = code.get(i);
            if (instruction.isCall()) {
                break;
            }
            if (instruction.moveSource >= 0 && instruction.destination == target) {
                target = instruction.moveSource;
                continue;
            }
            if (writes(instruction, target)) {
                if (isLdrb(instruction.word) && (instruction.word & 31) == target
                        && base(instruction.word) == agentBase && states[i] != null
                        && states[i].registers[agentBase]) {
                    return unsignedOffset(instruction.word, 1);
                }
                return -1;
            }
            if (!instruction.semanticsKnown) {
                return -1;
            }
        }
        return -1;
    }

    private static boolean writes(Instruction instruction, int register) {
        return instruction.destination == register || instruction.secondDestination == register
                || instruction.writeback == register;
    }

    private static List<Instruction> decode(byte[] bytes) {
        if (bytes.length == 0 || (bytes.length & 3) != 0) {
            throw invalid("AArch64 function is not a nonempty instruction array");
        }
        int count = bytes.length / 4;
        if (count > MAX_INSTRUCTIONS) {
            throw invalid("Native function exceeds the AArch64 instruction limit");
        }
        List<Instruction> result = new ArrayList<Instruction>(count);
        for (int i = 0; i < count; i++) {
            int offset = i * 4;
            int word = (bytes[offset] & 0xff) | (bytes[offset + 1] & 0xff) << 8
                    | (bytes[offset + 2] & 0xff) << 16 | (bytes[offset + 3] & 0xff) << 24;
            Instruction instruction = new Instruction(i, word);
            decodeSemantics(instruction);
            if (!instruction.isCall() && instruction.hasBranchTarget()
                    && (instruction.branchTarget < 0 || instruction.branchTarget >= count)) {
                throw invalid("AArch64 branch escapes the resolved function");
            }
            result.add(instruction);
        }
        return result;
    }

    private static void decodeSemantics(Instruction instruction) {
        int word = instruction.word;
        if (isDirectMove(word)) {
            instruction.destination = word & 31;
            instruction.moveSource = (word >>> 16) & 31;
            instruction.semanticsKnown = true;
            return;
        }
        if (instruction.isCall() || instruction.isReturn() || instruction.isIndirectJump()
                || instruction.hasBranchTarget() || isConditionalCompare(word)
                || isVectorZeroing(word) || word == 0xd503201f) {
            instruction.semanticsKnown = true;
            return;
        }
        boolean vectorPair = isVectorLoadStorePair(word);
        if (isLoadStorePair(word) || vectorPair) {
            instruction.semanticsKnown = true;
            if (!vectorPair && (word & 0x00400000) != 0) {
                instruction.destination = word & 31;
                instruction.secondDestination = (word >>> 10) & 31;
            }
            if ((word & 0x00800000) != 0 || (word & 0x01000000) == 0) {
                instruction.writeback = base(word);
            }
            return;
        }
        boolean vectorSingle = isVectorSingleLoadStore(word);
        boolean vectorLiteral = isVectorLiteralLoad(word);
        if (isSingleLoadStore(word) || isLiteralLoad(word) || vectorSingle || vectorLiteral) {
            instruction.semanticsKnown = true;
            if (!vectorSingle && !vectorLiteral
                    && ((word & 0x00400000) != 0 || isLiteralLoad(word))) {
                instruction.destination = word & 31;
            }
            if ((isSingleLoadStore(word) || vectorSingle) && hasSingleLoadStoreWriteback(word)) {
                instruction.writeback = base(word);
            }
            return;
        }
        if (matches(word, 0x1f000000, 0x11000000)
                || matches(word, 0x1f000000, 0x0b000000)
                || matches(word, 0x1f000000, 0x0a000000)
                || matches(word, 0x1f000000, 0x12000000)
                || matches(word, 0x1f800000, 0x12800000)
                || matches(word, 0x1f000000, 0x10000000)
                || matches(word, 0x1f800000, 0x1a800000)
                || matches(word, 0x1f800000, 0x13000000)
                || matches(word, 0x1f800000, 0x13800000)
                || matches(word, 0x1f000000, 0x1b000000)) {
            instruction.destination = word & 31;
            instruction.semanticsKnown = true;
        }
    }

    private static boolean isDirectMove(int word) {
        return matches(word, 0x7fe0ffe0, 0x2a0003e0);
    }

    private static boolean isConditionalCompare(int word) {
        return matches(word, 0x1f800000, 0x1a000000);
    }

    private static boolean isVectorZeroing(int word) {
        return word == 0x0f000400 || word == 0x4f000400;
    }

    private static boolean isVectorLoadStorePair(int word) {
        return matches(word, 0x3a000000, 0x28000000) && (word & 0x04000000) != 0;
    }

    private static boolean isVectorSingleLoadStore(int word) {
        return matches(word, 0x3a000000, 0x38000000) && (word & 0x04000000) != 0;
    }

    private static boolean isVectorLiteralLoad(int word) {
        return matches(word, 0x3b000000, 0x18000000) && (word & 0x04000000) != 0;
    }

    private static boolean hasSingleLoadStoreWriteback(int word) {
        if ((word & 0x01000000) != 0) {
            return false;
        }
        int addressingMode = (word >>> 10) & 3;
        return addressingMode == 1 || addressingMode == 3;
    }

    private static boolean isLoadStorePair(int word) {
        return matches(word, 0x3a000000, 0x28000000) && (word & 0x04000000) == 0;
    }

    private static boolean isSingleLoadStore(int word) {
        return matches(word, 0x3a000000, 0x38000000) && (word & 0x04000000) == 0;
    }

    private static boolean isLiteralLoad(int word) {
        return matches(word, 0x3b000000, 0x18000000) && (word & 0x04000000) == 0;
    }

    private static boolean isStr64(int word) {
        return matches(word, 0xffc00000, 0xf9000000);
    }

    private static boolean isLdr64(int word) {
        return matches(word, 0xffc00000, 0xf9400000);
    }

    private static boolean isStp64(int word) {
        return matches(word, 0xffc00000, 0xa9000000);
    }

    private static boolean isLdrb(int word) {
        return matches(word, 0xffc00000, 0x39400000);
    }

    private static boolean isStrb(int word) {
        return matches(word, 0xffc00000, 0x39000000);
    }

    private static int base(int word) {
        return (word >>> 5) & 31;
    }

    private static int unsignedOffset(int word, int scale) {
        return ((word >>> 10) & 0xfff) * scale;
    }

    private static int pairDisplacement(int word) {
        int immediate = (word >>> 15) & 0x7f;
        if ((immediate & 0x40) != 0) {
            immediate -= 0x80;
        }
        return immediate * 8;
    }

    private static boolean matches(int word, int mask, int expected) {
        return (word & mask) == expected;
    }

    private static int signExtend(int value, int bits) {
        int sign = 1 << (bits - 1);
        return (value ^ sign) - sign;
    }

    private static UnsupportedOperationException invalid(String message) {
        return new UnsupportedOperationException(message + "; native state was not changed");
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
        private final boolean[] registers = new boolean[31];

        private State copy() {
            State result = new State();
            System.arraycopy(registers, 0, result.registers, 0, registers.length);
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
            return changed;
        }
    }

    private static final class Instruction {
        private final int index;
        private final int word;
        private int destination = -1;
        private int secondDestination = -1;
        private int writeback = -1;
        private int moveSource = -1;
        private boolean semanticsKnown;
        private int branchTarget = -1;

        private Instruction(int index, int word) {
            this.index = index;
            this.word = word;
            if ((word & 0x7c000000) == 0x14000000) {
                branchTarget = index + signExtend(word & 0x03ffffff, 26);
            } else if ((word & 0xff000010) == 0x54000000) {
                branchTarget = index + signExtend((word >>> 5) & 0x7ffff, 19);
            } else if ((word & 0x7e000000) == 0x34000000) {
                branchTarget = index + signExtend((word >>> 5) & 0x7ffff, 19);
            } else if ((word & 0x7e000000) == 0x36000000) {
                branchTarget = index + signExtend((word >>> 5) & 0x3fff, 14);
            }
        }

        private boolean isCall() {
            return (word & 0xfc000000) == 0x94000000 || isBlr();
        }

        private boolean isBlr() {
            return (word & 0xfffffc1f) == 0xd63f0000;
        }

        private boolean isReturn() {
            return (word & 0xfffffc1f) == 0xd65f0000;
        }

        private boolean isIndirectJump() {
            return (word & 0xfffffc1f) == 0xd61f0000;
        }

        private boolean isUnconditionalBranch() {
            return (word & 0xfc000000) == 0x14000000;
        }

        private boolean isConditionalBranch() {
            return hasBranchTarget() && !isCall() && !isUnconditionalBranch();
        }

        private boolean hasBranchTarget() {
            return branchTarget != -1 || (word & 0x7c000000) == 0x14000000
                    || (word & 0xff000010) == 0x54000000
                    || (word & 0x7e000000) == 0x34000000
                    || (word & 0x7e000000) == 0x36000000;
        }
    }
}
