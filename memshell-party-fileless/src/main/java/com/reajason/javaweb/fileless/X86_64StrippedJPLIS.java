package com.reajason.javaweb.fileless;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Recovers internal JPLIS functions from JNI/Agent call graphs when symbols are stripped. */
final class X86_64StrippedJPLIS {
    private X86_64StrippedJPLIS() {
    }

    static Recovered recover(NativeImage image, boolean warningRequired) throws IOException {
        Elf64File.Symbol onLoad = required(image.findSymbol("Agent_OnLoad"), "Agent_OnLoad");
        Elf64File.Symbol onAttach = required(image.findSymbol("Agent_OnAttach"), "Agent_OnAttach");
        X86_64JPLISLayout.Call[] onLoadCalls = X86_64JPLISLayout.directCalls(
                image.readFunction(onLoad), onLoad.value);
        X86_64JPLISLayout.Call[] onAttachCalls = X86_64JPLISLayout.directCalls(
                image.readFunction(onAttach), onAttach.value);

        Elf64File.Symbol loadCreateNew = firstCommonFunction(
                image, onLoadCalls, onAttachCalls);
        Elf64File.Symbol attachCreateNew = firstCommonFunction(
                image, onAttachCalls, onLoadCalls);
        if (loadCreateNew == null || attachCreateNew == null) {
            throw invalid("Could not recover createNewJPLISAgent call graph");
        }
        if (loadCreateNew.value != attachCreateNew.value) {
            throw invalid("Ambiguous createNewJPLISAgent call graphs");
        }
        Elf64File.Symbol createNew = loadCreateNew;

        Elf64File.Symbol retransformWrapper = required(image.findSymbol(
                "Java_sun_instrument_InstrumentationImpl_retransformClasses0"), "retransform JNI");
        long retransformAddress = X86_64JPLISLayout.directTailJump(
                image.readFunction(retransformWrapper), retransformWrapper.value);
        Elf64File.Symbol retransform = required(image.functionAt(retransformAddress),
                "retransformClasses function range");
        X86_64JPLISLayout.Call[] retransformCalls = X86_64JPLISLayout.directCalls(
                image.readFunction(retransform), retransform.value);
        Elf64File.Symbol retransformableEnvironment = null;
        for (int i = 0; i < retransformCalls.length; i++) {
            Elf64File.Symbol candidate = image.functionAt(retransformCalls[i].target);
            if (candidate != null) {
                retransformableEnvironment = candidate;
                break;
            }
        }
        retransformableEnvironment = required(retransformableEnvironment,
                "retransformableEnvironment call graph");

        List<Elf64File.Symbol> common = commonFunctions(image, onLoadCalls, onAttachCalls);
        Elf64File.Symbol convertCapabilities = null;
        for (int i = 0; i < common.size(); i++) {
            Elf64File.Symbol candidate = common.get(i);
            boolean matches = false;
            try {
                X86_64JPLISLayout.Call[] calls = X86_64JPLISLayout.directCalls(
                        image.readFunction(candidate), candidate.value);
                matches = contains(calls, retransformableEnvironment.value);
            } catch (UnsupportedOperationException ignored) {
                // A candidate is usable only after its complete bounded decode succeeds.
            }
            if (matches) {
                if (convertCapabilities != null) {
                    throw invalid("Ambiguous capability conversion functions");
                }
                convertCapabilities = candidate;
            }
        }
        convertCapabilities = required(convertCapabilities, "capability conversion call graph");

        Elf64File.Symbol addRedefine = null;
        X86_64JPLISLayout.Call[] capabilityCalls = X86_64JPLISLayout.directCallsAndTailJumps(
                image.readFunction(convertCapabilities), convertCapabilities.value);
        for (int i = 0; i < capabilityCalls.length; i++) {
            Elf64File.Symbol candidate = image.functionAt(capabilityCalls[i].target);
            if (candidate == null || candidate.value == retransformableEnvironment.value) {
                continue;
            }
            boolean matches = false;
            try {
                byte[] code = image.readFunction(candidate);
                matches = X86_64JPLISLayout.hasIndirectCall(code, 0x2c0)
                        && X86_64JPLISLayout.hasIndirectCall(code, 0x468)
                        // jvmtiCapabilities.can_redefine_classes is bit 1.
                        && X86_64JPLISLayout.hasOrImmediate(code, 0x02);
            } catch (UnsupportedOperationException ignored) {
            }
            if (matches) {
                if (addRedefine != null) {
                    throw invalid("Ambiguous redefine-capability functions");
                }
                addRedefine = candidate;
            }
        }
        addRedefine = required(addRedefine, "addRedefineClassesCapability semantics");

        List<Elf64File.Symbol> initializers = calledFunctions(image, X86_64JPLISLayout.directCalls(
                image.readFunction(createNew), createNew.value));
        List<Elf64File.Symbol> attachFunctions = calledFunctions(image, onAttachCalls);
        Elf64File.Symbol createInstrumentation = null;
        Elf64File.Symbol initialize = null;
        X86_64JPLISLayout.Layout layout = null;
        for (int i = 0; i < attachFunctions.size(); i++) {
            Elf64File.Symbol candidate = attachFunctions.get(i);
            if (candidate.value == createNew.value || candidate.value == convertCapabilities.value
                    || !calledAfter(onAttachCalls, convertCapabilities.value, candidate.value)) {
                continue;
            }
            byte[] createCode;
            try {
                createCode = image.readFunction(candidate);
            } catch (UnsupportedOperationException ignored) {
                continue;
            }
            if (!warningRequired) {
                X86_64JPLISLayout.Layout candidateLayout = null;
                try {
                    candidateLayout = X86_64JPLISLayout.analyze(createCode, null, false);
                } catch (UnsupportedOperationException ignored) {
                }
                if (candidateLayout != null) {
                    if (createInstrumentation != null) {
                        throw invalid("Ambiguous stripped InstrumentationImpl creators");
                    }
                    createInstrumentation = candidate;
                    layout = candidateLayout;
                }
            } else {
                for (int j = 0; j < initializers.size(); j++) {
                    Elf64File.Symbol initializer = initializers.get(j);
                    X86_64JPLISLayout.Layout candidateLayout = null;
                    try {
                        candidateLayout = X86_64JPLISLayout.analyze(
                                createCode, image.readFunction(initializer), true);
                    } catch (UnsupportedOperationException ignored) {
                    }
                    if (candidateLayout != null) {
                        if (createInstrumentation != null) {
                            throw invalid("Ambiguous stripped JPLIS creator/initializer pairs");
                        }
                        createInstrumentation = candidate;
                        initialize = initializer;
                        layout = candidateLayout;
                    }
                }
            }
        }
        createInstrumentation = required(createInstrumentation,
                "createInstrumentationImpl data flow");

        Elf64File.Symbol setLive = null;
        for (int i = 0; i < attachFunctions.size(); i++) {
            Elf64File.Symbol candidate = attachFunctions.get(i);
            if (!calledAfter(onAttachCalls, createInstrumentation.value, candidate.value)) {
                continue;
            }
            boolean matches = false;
            try {
                matches = X86_64JPLISLayout.hasIndirectCall(image.readFunction(candidate), 0x3c8);
            } catch (UnsupportedOperationException ignored) {
            }
            if (matches) {
                if (setLive != null) {
                    throw invalid("Ambiguous live-phase event handlers");
                }
                setLive = candidate;
            }
        }
        setLive = required(setLive, "setLivePhaseEventHandlers semantics");

        Elf64File.Symbol hostWrapper = required(image.findSymbol(
                "Java_sun_instrument_InstrumentationImpl_setNativeMethodPrefixes"), "host JNI");
        long hostAddress = X86_64JPLISLayout.directTailJump(
                image.readFunction(hostWrapper), hostWrapper.value);
        Elf64File.Symbol host = required(image.functionAt(hostAddress),
                "setNativeMethodPrefixes function range");
        if (!X86_64JPLISLayout.hasIndirectCall(image.readFunction(host), 0x558)) {
            throw invalid("Recovered native host lacks its JVMTI call");
        }
        return new Recovered(createNew, addRedefine, retransformableEnvironment,
                createInstrumentation, setLive, initialize, host, layout);
    }

    private static Elf64File.Symbol firstCommonFunction(
            NativeImage image, X86_64JPLISLayout.Call[] calls,
            X86_64JPLISLayout.Call[] other) throws IOException {
        for (int i = 0; i < calls.length; i++) {
            Elf64File.Symbol candidate = image.functionAt(calls[i].target);
            if (candidate != null && contains(other, candidate.value)) {
                return candidate;
            }
        }
        return null;
    }

    private static List<Elf64File.Symbol> commonFunctions(
            NativeImage image, X86_64JPLISLayout.Call[] first,
            X86_64JPLISLayout.Call[] second) throws IOException {
        List<Elf64File.Symbol> result = new ArrayList<Elf64File.Symbol>();
        for (int i = 0; i < first.length; i++) {
            Elf64File.Symbol candidate = image.functionAt(first[i].target);
            if (candidate != null && contains(second, candidate.value)
                    && !contains(result, candidate.value)) {
                result.add(candidate);
            }
        }
        return result;
    }

    private static List<Elf64File.Symbol> calledFunctions(
            NativeImage image, X86_64JPLISLayout.Call[] calls) throws IOException {
        List<Elf64File.Symbol> result = new ArrayList<Elf64File.Symbol>();
        for (int i = 0; i < calls.length; i++) {
            Elf64File.Symbol candidate = image.functionAt(calls[i].target);
            if (candidate != null && !contains(result, candidate.value)) {
                result.add(candidate);
            }
        }
        return result;
    }

    private static boolean calledAfter(X86_64JPLISLayout.Call[] calls,
                                       long predecessor, long candidate) {
        int predecessorOffset = -1;
        for (int i = 0; i < calls.length; i++) {
            if (calls[i].target == predecessor) {
                predecessorOffset = calls[i].offset;
            }
        }
        if (predecessorOffset < 0) {
            return false;
        }
        for (int i = 0; i < calls.length; i++) {
            if (calls[i].target == candidate && calls[i].offset > predecessorOffset) {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(X86_64JPLISLayout.Call[] calls, long target) {
        for (int i = 0; i < calls.length; i++) {
            if (calls[i].target == target) {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(List<Elf64File.Symbol> symbols, long target) {
        for (int i = 0; i < symbols.size(); i++) {
            if (symbols.get(i).value == target) {
                return true;
            }
        }
        return false;
    }

    private static Elf64File.Symbol required(Elf64File.Symbol symbol, String description) {
        if (symbol == null) {
            throw invalid("Could not recover " + description);
        }
        return symbol;
    }

    private static UnsupportedOperationException invalid(String message) {
        return new UnsupportedOperationException(message + "; native state was not changed");
    }

    static final class Recovered {
        final Elf64File.Symbol createNew;
        final Elf64File.Symbol addRedefine;
        final Elf64File.Symbol retransformableEnvironment;
        final Elf64File.Symbol createInstrumentation;
        final Elf64File.Symbol setLive;
        final Elf64File.Symbol initialize;
        final Elf64File.Symbol host;
        final X86_64JPLISLayout.Layout layout;

        Recovered(Elf64File.Symbol createNew, Elf64File.Symbol addRedefine,
                  Elf64File.Symbol retransformableEnvironment,
                  Elf64File.Symbol createInstrumentation, Elf64File.Symbol setLive,
                  Elf64File.Symbol initialize, Elf64File.Symbol host,
                  X86_64JPLISLayout.Layout layout) {
            this.createNew = createNew;
            this.addRedefine = addRedefine;
            this.retransformableEnvironment = retransformableEnvironment;
            this.createInstrumentation = createInstrumentation;
            this.setLive = setLive;
            this.initialize = initialize;
            this.host = host;
            this.layout = layout;
        }
    }
}
