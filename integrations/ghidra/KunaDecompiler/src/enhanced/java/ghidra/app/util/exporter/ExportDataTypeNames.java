/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.exporter;

import java.util.*;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.DecompilerLanguage;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PartialUnion;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.pcode.PcodeDataTypeManager.ResultPartialDataType;
import ghidra.program.model.pcode.PcodeDataTypeManager.ResultQualifiedDataType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.IllegalCharCppTransformer;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Names belong to one export invocation, never to a source or result datatype manager. */
final class ExportDataTypeNames implements java.util.function.Function<DataType, String> {
	private final IdentityHashMap<DataType, String> names = new IdentityHashMap<>();
	private final Set<String> reserved = new HashSet<>();
	private final Set<String> sourceIdentifiers = new HashSet<>();
	private final List<FunctionDefinition> pendingSourceFunctions = new ArrayList<>();
	private final Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
	private final ArrayDeque<DataType> pending = new ArrayDeque<>();
	private final IllegalCharCppTransformer transformer = new IllegalCharCppTransformer();
	private final Program program;
	private final boolean emitDefinitions;
	private final Map<Long, ExternalFunction> externalFunctions = new LinkedHashMap<>();
	private boolean sourceNamesReserved;
	private boolean sourceFunctionAliases;
	private long nextName;

	record ExternalFunction(FunctionDefinition signature, String name, String importedName) {}

	ExportDataTypeNames(Program program, boolean emitDefinitions) {
		this.program = program;
		this.emitDefinitions = emitDefinitions;
	}

	Set<String> getReservedIdentifiers() {
		return Collections.unmodifiableSet(reserved);
	}

	void reserveIdentifier(String name) {
		sourceIdentifiers.add(reserve(name));
	}

	void reserveProgramSourceNames(TaskMonitor monitor) throws CancelledException {
		if (sourceNamesReserved) {
			return;
		}
		if (emitDefinitions) {
			reserveIdentifier(DataType.DEFAULT.getName());
			DataOrganization organization = program.getDataTypeManager().getDataOrganization();
			Iterator<DataType> builtins =
				BuiltInDataTypeManager.getDataTypeManager().getAllDataTypes();
			while (builtins.hasNext()) {
				monitor.checkCancelled();
				DataType type = builtins.next();
				if (type instanceof BuiltInDataType builtin && !(type instanceof Pointer) &&
					!(type instanceof FactoryDataType) && !(type instanceof Dynamic) &&
					builtin.getCTypeDeclaration(organization) != null) {
					reserveIdentifier(type.getName());
					if (type instanceof BuiltIn builtinType) {
						reserveIdentifier(
							builtinType.getDecompilerDisplayName(DecompilerLanguage.C_LANGUAGE));
					}
				}
			}
			for (var equates = program.getEquateTable().getEquates(); equates.hasNext();) {
				monitor.checkCancelled();
				reserveIdentifier(equates.next().getDisplayName());
			}
			var classes = program.getSymbolTable().getClassNamespaces();
			while (classes.hasNext()) {
				monitor.checkCancelled();
				String name = reserve(classes.next().getName());
				sourceIdentifiers.add(name);
				sourceIdentifiers.add("P" + name);
			}
		}
		Iterator<DataType> types = program.getDataTypeManager().getAllDataTypes();
		while (types.hasNext()) {
			reserveGraph(types.next(), null, monitor);
		}
		SymbolIterator symbols = program.getSymbolTable().getAllSymbols(false);
		while (symbols.hasNext()) {
			monitor.checkCancelled();
			sourceIdentifiers.add(reserve(symbols.next().getName()));
		}
		assignSourceFunctionNames(monitor);
		sourceNamesReserved = true;
	}

	boolean hasSourceFunctionAliases() {
		return sourceFunctionAliases;
	}

	/**
	 * Reserve used host temporary roots as well as source dependencies reached through local
	 * types. Managed source and NONDB objects keep their exact names and identities.
	 */
	void reserveSources(DecompileResults result, TaskMonitor monitor)
			throws CancelledException {
		if (result.isEnhancedResult()) {
			result.requireCurrentExportAuthority();
		}
		if (result.getExportBinding() != null) {
			for (String name : result.getExportBinding().getDeclarationNames()) {
				monitor.checkCancelled();
				reserve(name);
			}
		}
		// Import identity and formal types are source facts, not enhanced result metadata.
		collectExternalFunctions(result, monitor);
		PcodeDataTypeManager view = result.getDataTypeManager();
		if (view == null) {
			assignSourceFunctionNames(monitor);
			return;
		}
		reserveProgramSourceNames(monitor);
		for (DataType type : view.getRetainedSourceDataTypes()) {
			reserveGraph(type, view, monitor);
		}
		for (DataType type : result.getResultDataTypes()) {
			reserveGraph(type, view, monitor);
		}
		assignSourceFunctionNames(monitor);
	}

	Collection<ExternalFunction> externalFunctions() {
		return externalFunctions.values();
	}

	private void collectExternalFunctions(DecompileResults result, TaskMonitor monitor)
			throws CancelledException {
		if (result.getHighFunction() == null) {
			return;
		}
		for (var ops = result.getHighFunction().getPcodeOps(); ops.hasNext();) {
			monitor.checkCancelled();
			var op = ops.next();
			if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() == 0) {
				continue;
			}
			Function function =
				program.getFunctionManager().getFunctionAt(op.getInput(0).getAddress());
			if (function != null && function.isThunk()) {
				function = function.getThunkedFunction(true);
			}
			if (function == null || !function.isExternal() ||
				externalFunctions.containsKey(function.getSymbol().getID())) {
				continue;
			}
			// This adds bindings only where source and target prove them. Ineligible imports
			// retain the exporter's existing declaration/body behavior, not a new refusal.
			String format = program.getExecutableFormat();
			if (!MachoLoader.MACH_O_NAME.equals(format) && !ElfLoader.ELF_NAME.equals(format)) {
				continue;
			}
			String convention = function.getCallingConventionName();
			var defaultModel = program.getCompilerSpec().getDefaultCallingConvention();
			String defaultConvention = defaultModel == null ? null : defaultModel.getName();
			if (function.hasCustomVariableStorage()) {
				continue;
			}
			if (convention != null && !Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention) &&
				!Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention) &&
				!Objects.equals(defaultConvention, convention)) {
				continue;
			}
			ExternalLocation location =
				program.getExternalManager().getExternalLocation(function.getSymbol());
			String importedName = location == null ? null : location.getOriginalImportedName();
			if (importedName == null && location != null &&
				location.getSource() == SourceType.IMPORTED) {
				importedName = location.getLabel();
			}
			if (importedName == null || importedName.isEmpty()) {
				continue;
			}
			boolean printable = true;
			for (int i = 0; i < importedName.length(); i++) {
				char ch = importedName.charAt(i);
				if (ch < 32 || ch > 126) {
					printable = false;
					break;
				}
			}
			if (!printable) {
				continue;
			}
			FunctionDefinitionDataType signature = new FunctionDefinitionDataType(function, true);
			// This root describes an external function declaration, not a named function type.
			// Only its dependencies may acquire nominal datatype presentation names.
			reserveGraph(signature.getReturnType(), null, monitor);
			for (ParameterDefinition parameter : signature.getArguments()) {
				reserveGraph(parameter.getDataType(), null, monitor);
			}
			externalFunctions.put(function.getSymbol().getID(),
				new ExternalFunction(signature, transformer.simplify(function.getName()), importedName));
		}
	}

	private void enqueue(DataType type) {
		if (type != null && visited.add(type)) {
			pending.addLast(type);
		}
	}

	private void reserveGraph(DataType root, PcodeDataTypeManager view, TaskMonitor monitor)
			throws CancelledException {
		enqueue(root);
		while (!pending.isEmpty()) {
			monitor.checkCancelled();
			DataType type = pending.removeFirst();
			if (view == null || !view.isResultLocal(type)) {
				reserve(type.getName());
				reserve(type.getDisplayName());
				if (type instanceof FunctionDefinition function && !type.getName().isEmpty() &&
					!names.containsKey(type)) {
					names.put(type, type.getDisplayName());
					pendingSourceFunctions.add(function);
				}
				else if (type instanceof TypeDef || type instanceof Composite ||
					type instanceof ghidra.program.model.data.Enum || type instanceof BuiltInDataType) {
					sourceIdentifiers.add(reserve(type.getName()));
					sourceIdentifiers.add(reserve(type.getDisplayName()));
					if (type instanceof Composite) {
						sourceIdentifiers.add("P" + transformer.simplify(type.getDisplayName()));
					}
				}
				if (type instanceof ghidra.program.model.data.Enum enumm) {
					String macroName = emitDefinitions ? DataTypeWriter.getEnumMacroName(enumm) : null;
					if (macroName != null) {
						reserveIdentifier(macroName);
					}
					for (String name : enumm.getNames()) {
						sourceIdentifiers.add(reserve(name));
					}
				}
			}
			if (type instanceof ResultPartialDataType partial) {
				enqueue(partial.getParentDataType());
				enqueue(partial.getStrippedDataType());
			}
			else if (type instanceof PartialUnion partial) {
				enqueue(partial.getParent());
				enqueue(partial.getStrippedDataType());
			}
			else if (type instanceof TypeDef typedef) {
				enqueue(typedef.getDataType());
			}
			else if (type instanceof Pointer pointer) {
				enqueue(pointer.getDataType());
			}
			else if (type instanceof Array array) {
				enqueue(array.getDataType());
			}
			else if (type instanceof BitFieldDataType bitfield) {
				enqueue(bitfield.getBaseDataType());
			}
			else if (type instanceof Composite composite) {
				for (DataTypeComponent component : composite.getDefinedComponents()) {
					enqueue(component.getDataType());
				}
			}
			else if (type instanceof FunctionDefinition function) {
				enqueue(function.getReturnType());
				for (ParameterDefinition parameter : function.getArguments()) {
					enqueue(parameter.getDataType());
				}
			}
			else if (type instanceof Dynamic dynamic) {
				enqueue(dynamic.getReplacementBaseType());
			}
		}
	}

	private String reserve(String name) {
		reserved.add(name);
		reserved.add("P" + name);
		String outputName = transformer.simplify(name);
		reserved.add(outputName);
		reserved.add("P" + outputName);
		return outputName;
	}

	private void assignSourceFunctionNames(TaskMonitor monitor) throws CancelledException {
		for (FunctionDefinition function : pendingSourceFunctions) {
			monitor.checkCancelled();
			String name = function.getDisplayName();
			if (!isCIdentifier(name) || sourceIdentifiers.contains(name)) {
				// Source function types share C's ordinary identifier namespace with typedefs,
				// enum constants and symbols, regardless of their distinct source categories.
				String stem = transformer.simplify(name);
				// The symbol transformer deliberately also accepts C++ operators/templates.
				name = allocateName(isCIdentifier(stem) ? stem : "function");
				sourceFunctionAliases = true;
			}
			names.put(function, name);
			sourceIdentifiers.add(name);
		}
		pendingSourceFunctions.clear();
	}

	private static boolean isCIdentifier(String name) {
		if (name.isEmpty()) {
			return false;
		}
		for (int i = 0; i < name.length(); i++) {
			if (!isCIdentifierCharacter(name.charAt(i), i == 0)) {
				return false;
			}
		}
		return switch (name) {
			case "auto", "break", "case", "char", "const", "continue", "default", "do",
					"double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
					"int", "long", "register", "restrict", "return", "short", "signed", "sizeof",
					"static", "struct", "switch", "typedef", "union", "unsigned", "void",
					"volatile", "while", "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex",
					"_Generic", "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local" -> false;
			default -> true;
		};
	}

	private static boolean isCIdentifierCharacter(char ch, boolean first) {
		return ch == '_' || Character.isLetter(ch) ||
			!first && ch >= '0' && ch <= '9';
	}

	private String allocateName(DataType type) {
		return allocateName(transformer.simplify(type.getName()));
	}

	private String allocateName(String stem) {
		String name;
		do {
			name = stem + "_kuna_" + (++nextName);
		}
		while (reserved.contains(name) || reserved.contains("P" + name));
		reserve(name);
		return name;
	}

	void add(DecompileResults result) {
		if (!result.isEnhancedResult()) {
			return;
		}
		result.requireCurrentExportAuthority();
		for (DataType type : result.getResultDataTypes()) {
			if (!result.getDataTypeManager().isResultLocal(type) || names.containsKey(type) ||
				type instanceof ResultQualifiedDataType ||
				type instanceof ResultPartialDataType ||
				(type instanceof FunctionDefinition &&
					!result.getDataTypeManager().hasResultTypeName(type)) ||
				!(type instanceof Composite || type instanceof TypeDef ||
					type instanceof ghidra.program.model.data.Enum ||
					type instanceof FunctionDefinition)) {
				continue;
			}
			names.put(type, allocateName(type));
		}
	}

	@Override
	public String apply(DataType type) {
		return names.get(type);
	}
}
