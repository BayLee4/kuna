//! Invocation-local physical callable publication. Source prototypes remain on
//! their existing owners; only fresh export Funcdata receives these carriers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::space::spacetype;
use kuna_num::opcodes::OpCode;
use crate::architecture::Architecture;
use crate::dtype::{type_class, type_metatype, Datatype};
use crate::fspec::{FuncProto, ParameterPieces, PrototypePieces};
use crate::funcdata::Funcdata;

mod targets;

pub const ELEM_KUNA_EXPORT: kuna_base::marshal::ElementId = kuna_base::marshal::ElementId::new("kuna_export",4005);
pub const ELEM_KUNA_EXPORT_DECL: kuna_base::marshal::ElementId = kuna_base::marshal::ElementId::new("kuna_export_decl",4006);
pub const ATTRIB_KUNA_PRIVATE: kuna_base::marshal::AttributeId = kuna_base::marshal::AttributeId::new("kuna_private",4007);
pub const ATTRIB_KUNA_PUBLIC: kuna_base::marshal::AttributeId = kuna_base::marshal::AttributeId::new("kuna_public",4008);

#[derive(Clone, Debug)]
pub struct ExportDeclaration { pub index: u32, pub name: String, pub role: &'static str }
#[derive(Clone, Debug)]
pub struct ExportPublication {
    pub entry: Address, pub source_name: String, pub implementation: String,
    pub private: bool, pub public_prototype: i32, pub declarations: Vec<ExportDeclaration>,
}
impl ExportPublication {
    pub fn encode(&self, encoder:&mut dyn kuna_base::marshal::Encoder) -> KunaResult<()> {
        use kuna_base::marshal::{ATTRIB_NAME,ATTRIB_CONTENT,ATTRIB_INDEX};
        encoder.open_element(&ELEM_KUNA_EXPORT);
        encoder.write_string(&ATTRIB_NAME,self.source_name.as_bytes());
        encoder.write_string(&ATTRIB_CONTENT,self.implementation.as_bytes());
        encoder.write_bool(&ATTRIB_KUNA_PRIVATE,self.private);
        encoder.write_signed_integer(&ATTRIB_KUNA_PUBLIC,i64::from(self.public_prototype));
        self.entry.encode(encoder)?;
        for declaration in &self.declarations {
            encoder.open_element(&ELEM_KUNA_EXPORT_DECL);
            encoder.write_unsigned_integer(&ATTRIB_INDEX,u64::from(declaration.index));
            encoder.write_string(&ATTRIB_NAME,declaration.name.as_bytes());
            encoder.write_string(&ATTRIB_CONTENT,declaration.role.as_bytes());
            encoder.close_element(&ELEM_KUNA_EXPORT_DECL);
        }
        encoder.close_element(&ELEM_KUNA_EXPORT);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExportAddress { pub space: String, pub offset: u64 }
impl ExportAddress {
    pub fn new(address: &Address) -> Self {
        Self { space: address.get_space().map_or("", |s| s.get_name()).to_owned(), offset: address.get_offset() }
    }
    pub fn address(&self, arch: &Architecture) -> KunaResult<Address> {
        let space = arch.manage().get_space_by_name(&self.space)
            .ok_or_else(|| KunaError::lowlevel(format!("Unknown export address space {}", self.space)))?;
        Ok(Address::new(Rc::clone(space), self.offset))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExportCallKey { pub caller: ExportAddress, pub point: ExportAddress, pub ordinal: u32 }
#[derive(Clone, Debug, Default)]
pub struct ExportSourceSeed {
    pub model: Option<Rc<crate::fspec::ProtoModel>>,
    pub pending_proto: Option<PrototypePieces>,
    pub mapped_params: Vec<(i32,String,ParameterPieces)>,
    pub flow_overrides: Vec<(Address,u32)>,
}
#[derive(Clone, Debug)]
pub struct ExportEntry {
    pub entry: Address, pub name: String, pub size: i32,
    pub seed: ExportSourceSeed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportInputSpec {
    pub storage: ExportAddress, pub size: i32, pub source_slot: i32,
    pub unsigned: bool, pub name: String,
}
#[derive(Clone, Debug)]
pub struct ExportFunctionSpec {
    pub entry: ExportAddress, pub name: String, pub implementation: String,
    pub private: bool, pub wrapper: bool, pub inputs: Vec<ExportInputSpec>,
}
#[derive(Clone, Debug)]
pub struct ExportCallSpec {
    pub key: ExportCallKey, pub direct: Option<ExportAddress>,
    pub targets: Vec<ExportAddress>, pub inputs: Vec<ExportInputSpec>,
    pub helper: String,
}
#[derive(Clone, Debug, Default)]
pub struct ExportSpec {
    pub selected: Vec<ExportAddress>,
    pub functions: Vec<ExportFunctionSpec>, pub calls: Vec<ExportCallSpec>,
    pub failures: Vec<(ExportAddress, String)>,
    pub parameter_edits: Vec<ExportParameterEdit>,
}
/// Successful existing symbol directives bound to an exact working occurrence.
/// Datatypes remain on the assertion/type owners; workers rebind those same
/// original directive indexes instead of introducing a second datatype codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportParameterEdit {
    pub entry: ExportAddress, pub storage: ExportAddress, pub size:i32, pub slot:i32,
    pub name:String, pub printed:String, pub directives:Vec<usize>,
}
#[derive(Clone, Debug)]
pub struct ExportFunction {
    pub spec: ExportFunctionSpec, pub source: Rc<FuncProto>, pub canonical: Rc<FuncProto>, pub working: FuncProto,
}
#[derive(Clone, Debug)]
pub struct ExportCall {
    pub spec: ExportCallSpec, pub source: Rc<FuncProto>, pub working: FuncProto,
    pub source_geometry: Rc<FuncProto>,
    pub pointer: Option<Rc<Datatype>>, pub helper: String,
}
#[derive(Clone, Debug, Default)]
pub struct ExportBinding {
    parameter_edits:BTreeMap<ExportAddress,Vec<ExportParameterEdit>>,
    seeds: BTreeMap<ExportAddress,ExportSourceSeed>,
    selected: BTreeSet<ExportAddress>,
    functions: BTreeMap<ExportAddress, ExportFunction>,
    entry_index: BTreeMap<(i32,u64),ExportAddress>,
    calls: BTreeMap<ExportCallKey, Rc<ExportCall>>,
    call_index: BTreeMap<((i32,u64),(i32,u64),u32),Rc<ExportCall>>,
    failures: BTreeMap<ExportAddress, String>,
}
impl ExportBinding {
    pub fn parameter_edits(&self,entry:&Address) -> impl Iterator<Item=&ExportParameterEdit> {
        self.parameter_edits.get(&ExportAddress::new(entry)).into_iter().flatten()
    }

    /// Freeze edits already validated by the existing parameter directive owner.
    /// Machine call operands retain their raw carrier geometry; only the private
    /// implementation's typed formals change. Typed publication converts between
    /// those two value views explicitly.
    pub fn with_parameter_edits(
        &self,arch:&Architecture,edits:&[(ExportParameterEdit,Rc<Datatype>)],
    ) -> KunaResult<Self> {
        let mut binding = self.clone();
        for (edit,ty) in edits {
            let ty = arch.types_impl().ready_value_type(ty)?;
            let function = binding.functions.get_mut(&edit.entry)
                .filter(|function| function.spec.private)
                .ok_or_else(|| KunaError::lowlevel("Physical parameter edit has no private implementation"))?;
            let address = edit.storage.address(arch)?;
            let parameter = function.working.get_param(edit.slot)
                .filter(|parameter| parameter.get_address() == address
                    && parameter.get_size() == edit.size && ty.get_size() == edit.size)
                .ok_or_else(|| KunaError::lowlevel("Physical parameter edit no longer matches its exact occurrence"))?;
            let pieces = ParameterPieces {
                addr:address,type_:Some(ty),
                flags:parameter.get_flags() | crate::fspec::parameter_pieces_flags::TYPELOCK
                    | crate::fspec::parameter_pieces_flags::NAMELOCK,
            };
            function.working.set_param(edit.slot,&edit.name,&pieces);
            let stored = binding.parameter_edits.entry(edit.entry.clone()).or_default();
            stored.retain(|previous| previous.slot != edit.slot);
            stored.push(edit.clone());
            stored.sort_by_key(|edit| edit.slot);
        }
        Ok(binding)
    }
    pub fn source_seed(&self,entry:&Address) -> Option<&ExportSourceSeed> {
        self.seeds.get(&ExportAddress::new(entry))
    }
    pub fn contains(&self, entry:&Address) -> bool { self.selected.contains(&ExportAddress::new(entry)) }
    pub fn function(&self, entry: &Address) -> Option<&ExportFunction> {
        self.entry_index.get(&native_address(entry)?).and_then(|key| self.functions.get(key))
    }
    pub fn function_at(&self, entry: &ExportAddress) -> Option<&ExportFunction> { self.functions.get(entry) }
    pub(crate) fn bound_calls(&self,fd:&Funcdata) -> Vec<(i32,Rc<ExportCall>)> {
        let Some(caller) = native_address(fd.get_address()) else { return Vec::new(); };
        let mut ordinals = BTreeMap::new();
        let mut calls = Vec::new();
        for index in 0..fd.num_calls() {
            let actual = fd.get_call_specs(index);
            let Some(point) = fd.obank().get(actual.get_op()).and_then(|op| native_address(op.get_addr())) else { continue; };
            let ordinal = ordinals.entry(point).or_insert(0u32);
            if let Some(call) = self.call_index.get(&(caller,point,*ordinal)) {
                let site = fd.obank().get(actual.get_op()).expect("bound call operation").get_addr();
                let inferred = fd.get_override().is_inferred_proto_override(site,*ordinal);
                if emission_call_eligible(actual.proto(),inferred,
                    fd.get_override().is_authored_proto_override(site),true) {
                    calls.push((index,Rc::clone(call)));
                }
            }
            *ordinal += 1;
        }
        calls
    }
    pub fn calls_for<'a>(&'a self, entry: &'a Address) -> impl Iterator<Item=&'a ExportCall> {
        let caller = native_address(entry).unwrap_or((i32::MIN,0));
        self.call_index.range((caller,(i32::MIN,0),0)..)
            .take_while(move |(site,_)| site.0 == caller).map(|(_,call)| call.as_ref())
    }
    pub fn failure(&self, entry: &Address) -> Option<&str> { self.failures.get(&ExportAddress::new(entry)).map(String::as_str) }
    pub fn identifiers(&self) -> impl Iterator<Item=&str> {
        self.functions.values().map(|function| function.spec.implementation.as_str())
            .chain(self.calls.values().filter(|call| self.requires_helper(call)).map(|call| call.helper.as_str()))
    }
    pub(crate) fn requires_helper(&self,call:&ExportCall) -> bool {
        let Some(target) = call.spec.direct.as_ref().and_then(|entry| self.function_at(entry)) else { return true };
        call.spec.inputs.len() != target.spec.inputs.len()
            || call.spec.inputs.iter().zip(&target.spec.inputs).enumerate().any(|(slot,(a,b))|
                a.storage != b.storage || a.size != b.size
                    || !call.working.get_param(slot as i32).and_then(|p| p.get_type())
                        .zip(target.working.get_param(slot as i32).and_then(|p| p.get_type()))
                        .is_some_and(|(a,b)| Rc::ptr_eq(a,b)))
    }
    pub fn spec(&self) -> ExportSpec {
        ExportSpec { selected:self.selected.iter().cloned().collect(),
            functions: self.functions.values().map(|f| f.spec.clone()).collect(),
            calls: self.calls.values().map(|c| c.spec.clone()).collect(),
            failures: self.failures.iter().map(|(a,e)| (a.clone(), e.clone())).collect(),
            parameter_edits:self.parameter_edits.values().flatten().cloned().collect() }
    }
    pub fn from_spec(arch: &mut Architecture, spec: &ExportSpec) -> KunaResult<Self> {
        Self::from_spec_with_entries(arch,spec,&[])
    }
    pub fn from_spec_with_entries(arch:&mut Architecture,spec:&ExportSpec,entries:&[ExportEntry]) -> KunaResult<Self> {
        let required:BTreeSet<_> = spec.functions.iter().map(|function| function.entry.clone()).collect();
        let sources = entries.iter().filter(|entry| required.contains(&ExportAddress::new(&entry.entry))).map(|entry|
            effective_source(arch,entry).map(|(source,_)| (ExportAddress::new(&entry.entry),source)))
            .collect::<KunaResult<BTreeMap<_,_>>>()?;
        Self::from_spec_with_sources(arch,spec,entries,&sources)
    }
    fn from_spec_with_sources(arch:&mut Architecture,spec:&ExportSpec,entries:&[ExportEntry],
        sources:&BTreeMap<ExportAddress,Rc<FuncProto>>) -> KunaResult<Self>
    {
        let mut out = Self::default();
        for edit in &spec.parameter_edits {
            out.parameter_edits.entry(edit.entry.clone()).or_default().push(edit.clone());
        }
        out.seeds.extend(entries.iter().map(|entry| (ExportAddress::new(&entry.entry),entry.seed.clone())));
        out.selected.extend(spec.selected.iter().cloned());
        let mut reserved = arch.print().reserved_identifiers()
            .map(|names| names.as_ref().clone()).unwrap_or_default();
        reserved.extend(spec.functions.iter().flat_map(|function|
            [function.name.clone(), function.implementation.clone()]));
        for function in &spec.functions {
            let entry = function.entry.address(arch)?;
            let source = match sources.get(&function.entry) {
                Some(source) => Rc::clone(source),
                None => source_proto(arch, &entry)?.ok_or_else(|| KunaError::lowlevel("Prepared export source declaration is unavailable"))?,
            };
            let working = with_inputs(arch, &source, &function.inputs)?;
            let canonical = source_proto(arch,&entry)?.unwrap_or_else(|| Rc::clone(&source));
            out.entry_index.insert(native_address(&entry).expect("registered export entry"),function.entry.clone());
            out.functions.insert(function.entry.clone(), ExportFunction { spec: function.clone(), source, canonical, working });
        }
        for call in &spec.calls {
            let anchor = call.direct.as_ref().or_else(|| call.targets.first())
                .and_then(|target| out.functions.get(target))
                .ok_or_else(|| KunaError::lowlevel("Prepared export call target is unavailable"))?;
            let source = Rc::clone(&anchor.source);
            let source_geometry = Rc::new(arch.types_impl().acquire_working_proto(&source)?);
            let working = with_inputs(arch, &source, &call.inputs)?;
            let pointer = if call.direct.is_none() {
                let at = call.targets[0].address(arch)?;
                let code = arch.symboltab.find_function_across_scopes(&at)
                    .and_then(|(id,_)| arch.symboltab.symbol(id).dtype.clone())
                    .filter(|code| source_compatible_code(code,&source_geometry));
                // Loader symbols can retain generic Code even after a source
                // declaration arrives. Reuse only a complete matching signature;
                // otherwise build from source references, never working carriers.
                let code = match code { Some(code) => code, None => {
                    let mut pieces = PrototypePieces::default();
                    pieces.first_var_arg_slot = -1;
                    pieces.outtype = source.get_output_type().cloned();
                    for slot in 0..source.num_params() {
                        let parameter = source.get_param(slot).expect("source parameter");
                        pieces.intypes.push(parameter.get_type().cloned().ok_or_else(|| KunaError::lowlevel("Untyped export callback parameter"))?);
                        pieces.innames.push(parameter.get_name().to_owned());
                    }
                    arch.types_impl().get_type_code_proto_model(&pieces, Rc::clone(source.model()))?
                }};
                Some(arch.types().get_type_pointer(arch.manage().get_default_size(), code,
                    arch.manage().get_default_code_space().map_or(1, |s| s.get_word_size()))?)
            } else { None };
            let base = format!("kuna_call_{}_{:x}_{}_{:x}_{}",
                identifier(&call.key.caller.space),call.key.caller.offset,
                identifier(&call.key.point.space),call.key.point.offset,call.key.ordinal);
            let mut helper = if call.helper.is_empty() { base.clone() } else { call.helper.clone() };
            let mut suffix = 1;
            while call.helper.is_empty() && !reserved.insert(helper.clone()) {
                suffix += 1;
                helper = format!("{base}_{suffix}");
            }
            reserved.insert(helper.clone());
            let mut specification = call.clone();
            specification.helper = helper.clone();
            let caller = native_address(&call.key.caller.address(arch)?).expect("registered export caller");
            let point = native_address(&call.key.point.address(arch)?).expect("registered export callpoint");
            let binding = Rc::new(ExportCall { spec: specification, source, working, source_geometry, pointer, helper });
            out.call_index.insert((caller,point,call.key.ordinal),Rc::clone(&binding));
            out.calls.insert(call.key.clone(),binding);
        }
        out.failures.extend(spec.failures.iter().cloned());
        Ok(out)
    }

    /// Seed only ordinary, inferred call geometry. Actual authored site models,
    /// custom assembly and injection continue through their existing owners.
    pub(crate) fn seed_calls(&self, fd: &mut Funcdata) {
        for (index, call) in self.bound_calls(fd) {
            let actual = fd.get_call_specs(index);
            let Some(operation) = fd.obank().get(actual.get_op()) else { continue };
            if fd.get_override().is_authored_proto_override(operation.get_addr()) { continue; }
            let inferred = fd.get_override().is_inferred_proto_override(operation.get_addr(),call.spec.key.ordinal);
            if !binding_call_eligible(actual.proto(),inferred,true) { continue; }
            let proto = fd.get_call_specs_mut(index).proto_mut();
            let inferred_override = proto.is_override();
            proto.copy(&call.working);
            // Exact inferred provenance was checked above. Preserve
            // its existing restart/deindirect lock without granting a new
            // override to an ordinary call or accepting authored site state.
            if inferred_override { proto.set_override(true); }
        }
    }

    fn refine_function(&mut self,arch:&Architecture,entry:&ExportAddress,inputs:&[ExportInputSpec]) -> KunaResult<()> {
        let function = self.functions.get_mut(entry).expect("selected scalar export entry");
        function.working = with_inputs(arch,&function.source,inputs)?;
        function.spec.inputs = inputs.to_vec();
        Ok(())
    }

    fn refine_call(&mut self,arch:&Architecture,key:&ExportCallKey,inputs:&[ExportInputSpec]) -> KunaResult<()> {
        let old = self.calls.get(key).expect("selected physical occurrence");
        let mut specification = old.spec.clone();
        specification.inputs = inputs.to_vec();
        let call = Rc::new(ExportCall {
            spec:specification,source:Rc::clone(&old.source),
            working:with_inputs(arch,&old.source,inputs)?,
            source_geometry:Rc::clone(&old.source_geometry),
            pointer:old.pointer.clone(),helper:old.helper.clone(),
        });
        let caller = native_address(&key.caller.address(arch)?).expect("registered export caller");
        let point = native_address(&key.point.address(arch)?).expect("registered export callpoint");
        self.call_index.insert((caller,point,key.ordinal),Rc::clone(&call));
        self.calls.insert(key.clone(),call);
        Ok(())
    }
}

fn native_address(address:&Address) -> Option<(i32,u64)> {
    Some((address.get_space()?.get_index(),address.get_offset()))
}

pub(super) fn call_keys(fd: &Funcdata) -> Vec<ExportCallKey> {
    let caller = ExportAddress::new(fd.get_address());
    let mut ordinals = BTreeMap::new();
    (0..fd.num_calls()).map(|index| {
        let point = fd.obank().get(fd.get_call_specs(index).get_op()).expect("export call operation").get_addr();
        let ordinal = ordinals.entry(native_address(point)).or_insert(0u32);
        let key = ExportCallKey { caller:caller.clone(),point:ExportAddress::new(point),ordinal:*ordinal };
        *ordinal += 1;
        key
    }).collect()
}
fn identifier(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}
fn ordinary(proto: &FuncProto) -> bool {
    proto.has_model() && proto.has_store() && inferred_call_eligible(proto)
}
fn source_diagnostic(proto:&FuncProto) -> bool {
    proto.has_input_errors() || proto.has_output_errors()
}
fn inferred_call_eligible(proto: &FuncProto) -> bool {
    binding_call_eligible(proto,false,false)
}
fn emission_call_eligible(proto:&FuncProto,inferred:bool,authored:bool,pending:bool) -> bool {
    // Authored-site permission affects publication only, never inferred seeding.
    binding_call_eligible(proto,inferred || authored,pending)
}
fn binding_call_eligible(proto:&FuncProto,inferred_override:bool,pending_storage:bool) -> bool {
    !source_diagnostic(proto)
        && (!proto.is_override() || inferred_override) && !proto.has_custom_storage() && !proto.is_inline() && !proto.is_dotdotdot()
        && proto.get_inject_id() < 0 && proto.decoded_inject_name().is_none()
        // Fresh call occurrences precede ActionDefaultParams and may not yet
        // have a model. Their immutable binding was acquired from completed
        // source/site analysis; seeding supplies that working model. Never
        // dereference an absent model or erase actual model injection authority.
        && (!proto.has_model()
            || proto.get_inject_upon_entry() < 0 && proto.get_inject_upon_return() < 0)
        && (!proto.has_store() || (0..proto.num_params()).all(|slot| proto.get_param(slot).is_some_and(|p|
            !p.is_hidden_return() && !p.is_indirect_storage() && !p.is_this_pointer()
                && (p.get_address().get_space().is_some_and(|s| s.get_type() != spacetype::IPTR_JOIN)
                    || pending_storage && proto.logical_pieces().is_some() && p.get_address().is_invalid()))))
}

#[cfg(test)]
mod eligibility_tests {
    use super::{binding_call_eligible,inferred_call_eligible,modeled_extension_contains,ordinary,source_compatible_code};
    use crate::fspec::{FuncProto,ParameterPieces,PrototypePieces};

    #[test]
    fn modeled_entry_extensions_cover_only_their_actual_storage() {
        use std::rc::Rc;
        use kuna_base::address::Address;
        use kuna_base::space::{spacetype,AddrSpace,AddrSpaceManager};
        use kuna_num::{opcodes::OpCode,pcoderaw::VarnodeData};
        use crate::dtype::{type_class,type_metatype,Datatype};
        use crate::fspec::{param_entry_flags,ParamEntry,ParamListKind,ParamListStandard};
        use crate::kuna_narrowext::{or_model,Widen};

        for big_endian in [false,true] {
            let register = Rc::new(AddrSpace::new(
                spacetype::IPTR_PROCESSOR,"register",big_endian,8,1,3,0,0,0,
            ));
            let manager = AddrSpaceManager::new();
            let list = |class,flags| {
                let mut list = ParamListStandard::new(ParamListKind::Standard);
                list.push_entry(ParamEntry::seed(
                    0,class,Rc::clone(&register),0x10,8,1,0,flags,true,false,&[],&manager,
                ).unwrap());
                list.finish_decode();
                list
            };
            let zero = list(type_class::TYPECLASS_GENERAL,param_entry_flags::SMALLSIZE_ZEXT);
            let sign = list(type_class::TYPECLASS_GENERAL,param_entry_flags::SMALLSIZE_SEXT);
            let inttype = list(type_class::TYPECLASS_GENERAL,param_entry_flags::SMALLSIZE_INTTYPE);
            let unspecified = list(type_class::TYPECLASS_GENERAL,0);
            let floating = list(type_class::TYPECLASS_FLOAT,0);
            let whole = Address::new(Rc::clone(&register),0x10);
            let word = Address::new(Rc::clone(&register),if big_endian { 0x14 } else { 0x10 });
            for (size,metatype) in [
                (1,type_metatype::TYPE_INT),
                (2,type_metatype::TYPE_UINT),
                (1,type_metatype::TYPE_BOOL),
            ] {
                let ty = Datatype::new(size,metatype);
                let source = Address::new(Rc::clone(&register),if big_endian { 0x18-size as u64 } else { 0x10 });
                let covers = |rule,model:&ParamListStandard,at:&Address,width| {
                    modeled_extension_contains(rule,model,&source,size,&ty,at,width)
                };
                // Off still uses the model's zero extension, not the source
                // cast that accidentally made the original Apple control pass.
                let mut container = VarnodeData::default();
                assert_eq!(or_model(None,&zero,&source,size,Some(&ty),&mut container),
                    (OpCode::CPUI_INT_ZEXT,false));
                assert_eq!(or_model(Some(Widen::Word),&zero,&source,size,Some(&ty),&mut container),
                    (if metatype == type_metatype::TYPE_INT {
                        OpCode::CPUI_INT_SEXT
                    } else { OpCode::CPUI_INT_ZEXT },true));
                assert!(covers(None,&zero,&whole,8));
                assert!(covers(None,&sign,&whole,8));
                assert!(covers(None,&inttype,&whole,8));
                assert!(!covers(None,&unspecified,&word,4));
                assert!(covers(Some(Widen::Word),&zero,&word,4));
                assert!(!covers(Some(Widen::Word),&zero,&whole,8));
                assert!(covers(Some(Widen::Register),&unspecified,&whole,8));
                assert!(!covers(Some(Widen::Word),&floating,&word,4));
                let shifted = Address::new(Rc::clone(&register),word.get_offset()+1);
                assert!(!covers(Some(Widen::Word),&zero,&shifted,4));
                let before = Address::new(Rc::clone(&register),word.get_offset()-1);
                assert!(!covers(Some(Widen::Word),&zero,&before,4));
                let other = Rc::new(AddrSpace::new(
                    spacetype::IPTR_PROCESSOR,"other",big_endian,8,1,4,0,0,0,
                ));
                assert!(!covers(None,&zero,&Address::new(other,0x10),8));
                // A source at a non-justified offset has no modeled producer.
                let shifted_source = Address::new(Rc::clone(&register),source.get_offset()+1);
                assert!(!modeled_extension_contains(
                    Some(Widen::Word),&zero,&shifted_source,size,&ty,&word,4,
                ));
            }
            let source = Address::new(Rc::clone(&register),if big_endian { 0x17 } else { 0x10 });
            for metatype in [type_metatype::TYPE_PTR,type_metatype::TYPE_FLOAT,type_metatype::TYPE_UNKNOWN] {
                assert!(!modeled_extension_contains(
                    Some(Widen::Word),&unspecified,&source,1,&Datatype::new(1,metatype),&word,4,
                ));
            }
            // The raw Boolean carrier's type is unsigned, not BOOL. Neither
            // the model nor the stated rule changes ZEXT into normalization.
            let raw_byte = Datatype::new(1,type_metatype::TYPE_UINT);
            let mut container = VarnodeData::default();
            assert_eq!(or_model(Some(Widen::Word),&zero,&source,1,Some(&raw_byte),&mut container),
                (OpCode::CPUI_INT_ZEXT,true));
            // Register rules also cover a 32-bit unsigned source by sign,
            // whereas Word says nothing at that width and keeps the model.
            let unsigned_word = Datatype::new(4,type_metatype::TYPE_UINT);
            assert_eq!(or_model(Some(Widen::Register),&zero,&word,4,Some(&unsigned_word),&mut container),
                (OpCode::CPUI_INT_SEXT,true));
            assert!(modeled_extension_contains(
                Some(Widen::Register),&zero,&word,4,&unsigned_word,&whole,8,
            ));
            assert_eq!(or_model(Some(Widen::Word),&zero,&word,4,Some(&unsigned_word),&mut container),
                (OpCode::CPUI_INT_ZEXT,false));
            assert!(modeled_extension_contains(
                Some(Widen::Word),&zero,&word,4,&unsigned_word,&whole,8,
            ));
        }
    }

    #[test]
    fn callback_code_requires_complete_matching_source_signature_not_storage() {
        use std::rc::Rc;
        use kuna_base::address::Address;
        use kuna_base::space::AddrSpaceManager;
        use crate::dtype::{flags,Datatype,DatatypeKind,type_metatype};
        let result = Rc::new(Datatype::new(4,type_metatype::TYPE_INT));
        let parameter = Rc::new(Datatype::new(1,type_metatype::TYPE_UINT));
        let mut source = FuncProto::new();
        source.set_model(Some(Rc::new(crate::fspec::ProtoModel::new(&AddrSpaceManager::new()))));
        source.attach_internal_store(result);
        source.set_param(0,"value",&ParameterPieces {
            addr:Address::default(),type_:Some(Rc::clone(&parameter)),flags:0,
        });
        let mut code = Datatype::new(1,type_metatype::TYPE_CODE);
        code.kind = DatatypeKind::Code { proto:None };
        assert!(!source_compatible_code(&code,&source));
        let mut retained = FuncProto::new();
        retained.copy(&source);
        code.kind = DatatypeKind::Code { proto:Some(Rc::new(retained)) };
        // A C signature does not require assigned physical parameter storage.
        assert!(source.get_param(0).unwrap().get_address().is_invalid());
        assert!(source_compatible_code(&code,&source));
        code.flags |= flags::type_incomplete;
        assert!(!source_compatible_code(&code,&source));
        code.flags &= !flags::type_incomplete;
        let mut different_reference = FuncProto::new();
        different_reference.copy(&source);
        different_reference.set_param(0,"value",&ParameterPieces {
            addr:Address::default(),
            type_:Some(Rc::new(Datatype::new(1,type_metatype::TYPE_UINT))),flags:0,
        });
        code.kind = DatatypeKind::Code { proto:Some(Rc::new(different_reference)) };
        assert!(!source_compatible_code(&code,&source));
        let mut mismatch = FuncProto::new();
        mismatch.copy(&source);
        mismatch.set_param(0,"value",&ParameterPieces {
            addr:Address::default(),
            type_:Some(Rc::new(Datatype::new(4,type_metatype::TYPE_UINT))),flags:0,
        });
        code.kind = DatatypeKind::Code { proto:Some(Rc::new(mismatch)) };
        assert!(!source_compatible_code(&code,&source));
        let mut diagnostic = FuncProto::new();
        diagnostic.copy(&source);
        diagnostic.set_input_errors(true);
        code.kind = DatatypeKind::Code { proto:Some(Rc::new(diagnostic)) };
        assert!(!source_compatible_code(&code,&source));
    }

    #[test]
    fn fresh_call_can_receive_binding_without_claiming_source_eligibility() {
        let mut proto = FuncProto::new();
        assert!(!proto.has_model());
        assert!(!proto.has_store());
        assert!(inferred_call_eligible(&proto));
        assert!(!ordinary(&proto));
        proto.set_override(true);
        assert!(!inferred_call_eligible(&proto));
    }

    #[test]
    fn pending_logical_parameter_storage_requires_the_bound_acquisition_path() {
        use std::rc::Rc;
        use kuna_base::address::Address;
        use crate::dtype::{Datatype,type_metatype};
        let boolean = Rc::new(Datatype::new(1,type_metatype::TYPE_BOOL));
        let mut proto = FuncProto::new();
        proto.attach_internal_store(Rc::new(Datatype::new(0,type_metatype::TYPE_VOID)));
        proto.set_param(0,"value",&ParameterPieces {
            addr:Address::default(),type_:Some(Rc::clone(&boolean)),
            flags:crate::fspec::parameter_pieces_flags::TYPELOCK,
        });
        assert!(!binding_call_eligible(&proto,false,true));
        proto.retain_logical_declaration(&PrototypePieces {
            intypes:vec![boolean],first_var_arg_slot:-1,..PrototypePieces::default()
        });
        assert!(!inferred_call_eligible(&proto));
        assert!(binding_call_eligible(&proto,false,true));
        proto.set_override(true);
        assert!(!binding_call_eligible(&proto,false,true));
        assert!(binding_call_eligible(&proto,true,true));
        proto.set_input_errors(true);
        assert!(!binding_call_eligible(&proto,true,true));
        proto.set_input_errors(false);
        proto.set_output_errors(true);
        assert!(!binding_call_eligible(&proto,true,true));
    }
}

fn source_proto(arch: &mut Architecture, entry: &Address) -> KunaResult<Option<Rc<FuncProto>>> {
    if let Some(source) = arch.symboltab.function_source_proto_across_scopes(entry) { return Ok(Some(Rc::clone(source))); }
    if let Some(remote) = &arch.remote_scope { return Ok(remote.function_at(entry)?.and_then(|facts| facts.source_proto)); }
    Ok(None)
}
fn with_inputs(arch: &Architecture, source: &FuncProto, inputs: &[ExportInputSpec]) -> KunaResult<FuncProto> {
    if source_diagnostic(source) {
        return Err(KunaError::lowlevel("Source diagnostic cannot satisfy a prepared physical export binding"));
    }
    let mut working = arch.types_impl().acquire_working_proto(source)?;
    if source_diagnostic(&working) {
        return Err(KunaError::lowlevel("Physical export acquisition retained a source diagnostic"));
    }
    working.store_clear_all_inputs();
    for (slot, input) in inputs.iter().enumerate() {
        let ty = if input.unsigned { arch.types().get_base(input.size, type_metatype::TYPE_UINT)? }
            else { source.get_param(input.source_slot).and_then(|p| p.get_type()).cloned()
                .ok_or_else(|| KunaError::lowlevel("Prepared export source input is unavailable"))? };
        working.set_param(slot as i32, &input.name, &ParameterPieces {
            addr: input.storage.address(arch)?, type_: Some(ty),
            flags: crate::fspec::parameter_pieces_flags::TYPELOCK | crate::fspec::parameter_pieces_flags::NAMELOCK,
        });
    }
    working.set_input_lock(true);
    Ok(working)
}

/// Acquire the same selected invocation in remote and standalone front ends.
pub fn prepare_addresses(arch: &mut Architecture, selected: &[Address]) -> KunaResult<ExportBinding> {
    let entries = selected.iter().map(|entry| {
        let facts = arch.remote_scope.as_ref().map(|remote| remote.function_at(entry)).transpose()?.flatten();
        let name = facts.as_ref().map(|facts| facts.name.clone()).or_else(|| arch.symboltab.find_function_across_scopes(entry)
            .map(|(id,_)| arch.symboltab.symbol(id).get_name().to_owned())).unwrap_or_else(|| format!("sub_{:x}", entry.get_offset()));
        Ok(ExportEntry { entry: entry.clone(), name, size: 0, seed:ExportSourceSeed::default() })
    }).collect::<KunaResult<Vec<_>>>()?;
    prepare(arch, &entries)
}

/// Resolve actual selected call identities before installing physical carriers.
/// Raw entry evidence seeds widths; completed source-shaped analysis is used
/// only for callable identities, never as the machine-width oracle.
pub fn prepare(arch: &mut Architecture, selected: &[ExportEntry]) -> KunaResult<ExportBinding> {
    let mut spec = ExportSpec::default();
    spec.selected = selected.iter().map(|entry| ExportAddress::new(&entry.entry)).collect();
    let mut probes = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut geometries = BTreeMap::new();
    let mut authored_entries = BTreeSet::new();
    let Some(register) = arch.manage().get_space_by_name("register").cloned() else {
        return Ok(ExportBinding { selected:spec.selected.into_iter().collect(),
            seeds:selected.iter().map(|entry| (ExportAddress::new(&entry.entry),entry.seed.clone())).collect(),
            ..ExportBinding::default() });
    };
    for entry in selected {
        let key = ExportAddress::new(&entry.entry);
        let (source,authored) = match effective_source(arch,entry) {
            Ok(source) => source,
            Err(error @ KunaError::Transport { .. }) => return Err(error),
            Err(error) => { spec.failures.push((key,error.to_string())); continue; }
        };
        if authored { authored_entries.insert(key.clone()); }
        sources.insert(key.clone(), Rc::clone(&source));
        // This is an actual source-application outcome, not a failed physical
        // acquisition treated as absence. Keep the selected identity and its
        // ordinary body path; it cannot certify a private carrier binding.
        if source_diagnostic(&source) { continue; }
        let source_working = match arch.types_impl().acquire_working_proto(&source) {
            Ok(working) => working,
            Err(error @ KunaError::Transport { .. }) => return Err(error),
            Err(error) => { spec.failures.push((key,error.to_string())); continue; }
        };
        if !ordinary(&source_working) || !source_working.is_input_locked()
            || source.get_output_type().is_none()
        {
            continue;
        }
        let probe = match crate::kuna_calleedeadarg::probe_cached(arch, &entry.entry, register.get_index()) {
            Ok(probe) => probe,
            Err(error @ KunaError::Transport { .. }) => return Err(error),
            Err(error) => { spec.failures.push((key,error.to_string())); continue; }
        };
        let mut inputs = (0..source_working.num_params()).filter_map(|slot| source_working.get_param(slot).map(|p| ExportInputSpec {
            storage: ExportAddress::new(&p.get_address()), size: p.get_size(), source_slot: slot,
            unsigned: p.get_type().is_some_and(|t| t.get_metatype() == type_metatype::TYPE_BOOL),
            name: if p.get_name().is_empty() { format!("param_{}", slot + 1) } else { p.get_name().to_owned() },
        })).collect::<Vec<_>>();
        if let Some(probe) = &probe {
            for (space,offset,size) in probe.consumed_input_ranges() {
                if space != register.get_index() { continue; }
                add_input(arch, &source_working, &mut inputs, Address::new(Rc::clone(&register), offset), size)?;
            }
        }
        sources.insert(key.clone(), source);
        geometries.insert(key.clone(),source_working);
        if let Some(probe) = probe { probes.insert(key.clone(), probe); }
        spec.functions.push(ExportFunctionSpec { entry: key, name: entry.name.clone(), implementation: entry.name.clone(), private: false, wrapper: false, inputs });
    }
    // Only authored callers need preflight when entry geometry agrees. Retain
    // just the first mismatch's result; earlier matching callers are analyzed
    // again if full preparation becomes necessary, rather than retaining all IR.
    let physical_mismatch = spec.functions.iter().any(|f| differs(f.inputs.iter(),&geometries[&f.entry]));
    let mut preflight = None;
    let mut site_mismatch = false;
    for entry in selected {
        if physical_mismatch { break; }
        let key = ExportAddress::new(&entry.entry);
        if !authored_entries.contains(&key) { continue; }
        match analyze(arch,entry,None,None) {
            Ok(fd) => {
                for index in 0..fd.num_calls() {
                    let call = fd.get_call_specs(index);
                    let operation = fd.obank().get(call.get_op()).expect("authored call operation");
                    if operation.code() != OpCode::CPUI_CALL
                        || !fd.get_override().is_authored_proto_override(operation.get_addr()) { continue; }
                    let Some(source) = geometries.get(&ExportAddress::new(call.get_entry_address())) else { continue };
                    if emission_call_eligible(call.proto(),false,true,false) {
                        if let Some(inputs) = finalized_inputs(&fd,index,source) {
                            site_mismatch |= differs(inputs.iter().map(|input| &input.input),source)
                                || differs(inputs.iter().map(|input| &input.input),call.proto());
                        }
                    }
                }
                if site_mismatch {
                    preflight = Some((key,fd));
                    break;
                }
            }
            Err(error @ KunaError::Transport { .. }) => return Err(error),
            Err(error) => spec.failures.push((key,error.to_string())),
        }
    }
    // Most invocations have neither mismatch. Matching harmless overrides do
    // not force an unconditional analysis of every selected root.
    if !site_mismatch && !physical_mismatch {
        return Ok(ExportBinding { selected:spec.selected.into_iter().collect(),
            seeds:selected.iter().map(|entry| (ExportAddress::new(&entry.entry),entry.seed.clone())).collect(),
            failures: spec.failures.into_iter().collect(), ..ExportBinding::default() });
    }
    let mut flow = targets::TargetFlow::new(selected);
    let mut canonical_calls = Vec::new();
    let failed: BTreeSet<_> = spec.failures.iter().map(|(entry,_)| entry.clone()).collect();
    let mut reserved = arch.print().reserved_identifiers()
        .map(|names| names.as_ref().clone()).unwrap_or_default();
    for entry in selected {
        let key = ExportAddress::new(&entry.entry);
        if failed.contains(&key) { continue; }
        let prepared = if preflight.as_ref().is_some_and(|(entry,_)| entry == &key) {
            preflight.take().map(|(_,fd)| fd)
        } else { None };
        match prepared.map(Ok).unwrap_or_else(|| analyze(arch, entry, None, None)) {
            Ok(mut fd) => {
                let recorded = (|| -> KunaResult<_> {
                    flow.record(&fd)?;
                    let mut calls = Vec::new();
                    for (index,key) in call_keys(&fd).into_iter().enumerate() {
                        let index = index as i32;
                        let call = fd.get_call_specs(index);
                        let operation = fd.obank().get(call.get_op()).expect("call operation");
                        let inferred = fd.get_override().is_inferred_proto_override(operation.get_addr(),key.ordinal);
                        let authored = fd.get_override().is_authored_proto_override(operation.get_addr());
                        if !call.proto().has_model() || !call.proto().has_store()
                            || !emission_call_eligible(call.proto(),inferred,authored,false) { continue; }
                        if operation.code() == OpCode::CPUI_CALL {
                            let target = ExportAddress::new(call.get_entry_address());
                            let inputs = geometries.get(&target).and_then(|source|
                                finalized_inputs(&fd,index,source));
                            if authored && inputs.is_none() { continue; }
                            calls.push((key, Some(target),call.proto().clone(),inputs,authored));
                        } else if operation.code() == OpCode::CPUI_CALLIND {
                            let op = call.get_op();
                            let callee = operation.get_in(0);
                            let fallback = call.proto().clone();
                            let source = callee.map(|callee|
                                fd.vn_high_type_read_facing(callee,op)).transpose()?
                                .and_then(|pointer| pointer.get_ptr_to())
                                .and_then(|code| code.get_code_prototype().cloned());
                            let source = source.as_ref().map(|source|
                                arch.types_impl().acquire_working_proto(source)).transpose()?;
                            let source = match source {
                                Some(source) if ordinary(&source) => source,
                                Some(_) => continue,
                                None => fallback,
                            };
                            calls.push((key, None,source,None,false));
                        }
                    }
                    Ok(calls)
                })();
                match recorded {
                    Ok(calls) => canonical_calls.extend(calls),
                    Err(error @ KunaError::Transport { .. }) => return Err(error),
                    Err(error) => { spec.failures.push((key,error.to_string())); continue; }
                }
                reserved.extend(crate::decompile_drive::extract_variables(arch,&fd)?
                    .into_iter().map(|variable| variable.name));
            }
            Err(error @ KunaError::Transport { .. }) => return Err(error),
            Err(error) => spec.failures.push((key, error.to_string())),
        }
    }
    let known = flow.resolve();
    for ty in arch.types_impl().dependent_order() {
        if !ty.get_name().is_empty() {
            reserved.insert(ty.get_name().to_owned());
            reserved.insert(identifier(ty.get_name()));
        }
    }
    arch.print_mut().set_reserved_identifiers(Rc::new(reserved));
    let mut indirect = BTreeMap::<ExportAddress,Vec<ExportCallKey>>::new();
    for (site,direct,_,_,_) in &canonical_calls {
        if direct.is_none() { indirect.entry(site.caller.clone()).or_default().push(site.clone()); }
    }
    let function_indices: BTreeMap<_,_> = spec.functions.iter().enumerate()
        .map(|(index,function)| (function.entry.clone(),index)).collect();
    // Only dependency work is revisited as positive requirements grow. Each
    // range has a finite ABI carrier domain; a deep forwarder chain does not
    // trigger repeated unconditional scans of the selected inventory.
    let mut dependents = BTreeMap::<ExportAddress,BTreeSet<ExportAddress>>::new();
    for function in &spec.functions {
        if let Some(probe) = probes.get(&function.entry) {
            for (target,_) in probe.export_forwarded_inputs(|_| Vec::new()) {
                dependents.entry(ExportAddress::new(&target)).or_default().insert(function.entry.clone());
            }
        }
        for site in indirect.get(&function.entry).into_iter().flatten() {
            for target in known.get(site).into_iter().flatten() {
                dependents.entry(target.clone()).or_default().insert(function.entry.clone());
            }
        }
    }
    let mut queued: BTreeSet<_> = function_indices.keys().cloned().collect();
    let mut queue: VecDeque<_> = queued.iter().cloned().collect();
    while let Some(key) = queue.pop_front() {
        queued.remove(&key);
        let index = function_indices[&key];
        let mut inputs = spec.functions[index].inputs.clone();
        let source = &geometries[&key];
        if let Some(probe) = probes.get(&key) {
            for (_,ranges) in probe.export_forwarded_inputs(|target| {
                function_indices.get(&ExportAddress::new(target)).map(|&index|
                    spec.functions[index].inputs.iter().map(|input|
                        (input.storage.address(arch).expect("prepared export storage"),input.size)).collect())
                    .unwrap_or_default()
            }) {
                for (address,size) in ranges { add_input(arch,source,&mut inputs,address,size)?; }
            }
        }
        for site in indirect.get(&key).into_iter().flatten() {
            for target in known.get(site).into_iter().flatten() {
                if let Some(&index) = function_indices.get(target) {
                    for input in &spec.functions[index].inputs {
                        add_input(arch,source,&mut inputs,input.storage.address(arch)?,input.size)?;
                    }
                }
            }
        }
        if inputs == spec.functions[index].inputs { continue; }
        spec.functions[index].inputs = inputs;
        for caller in dependents.get(&key).into_iter().flatten() {
            if queued.insert(caller.clone()) { queue.push_back(caller.clone()); }
        }
    }
    let mut omitted = BTreeMap::<ExportAddress,BTreeSet<i32>>::new();
    for (_,direct,_,inputs,_) in &canonical_calls {
        let Some(target) = direct.as_ref() else { continue };
        let Some(inputs) = inputs else { continue };
        let Some(source) = geometries.get(target) else { continue };
        let Some(probe) = probes.get(target) else { continue };
        for slot in 0..source.num_params() {
            let parameter = source.get_param(slot).expect("source input");
            let address = parameter.get_address();
            if inputs.iter().any(|input| covers(&input.input,&address,parameter.get_size()))
                || !probe.returns_untouched(&address,parameter.get_size())
                || !output_disjoint(source,&address,parameter.get_size())
                || !output_disjoint(&sources[target],&address,parameter.get_size())
            { continue; }
            omitted.entry(target.clone()).or_default().insert(slot);
        }
    }
    let supplied_calls:BTreeMap<_,_> = canonical_calls.iter().filter_map(|(key,_,_,inputs,authored)|
        inputs.as_ref().map(|inputs| (key.clone(),(inputs.clone(),*authored)))).collect();
    for (key,direct,site_proto,supplied,authored) in canonical_calls {
        let targets = direct.as_ref().map(|target| vec![target.clone()]).unwrap_or_else(|| known.get(&key).cloned().unwrap_or_default())
            .into_iter().filter(|target| geometries.get(target).is_some_and(|source|
                direct.is_some() || same_signature(&site_proto,source))).collect::<Vec<_>>();
        let Some(anchor) = targets.first().and_then(|target| function_indices.get(target))
            .map(|&index| &spec.functions[index]) else { continue };
        let source = &geometries[&anchor.entry];
        let mut inputs = if authored { supplied.map(|inputs| inputs.into_iter().map(|input| input.input).collect())
                .unwrap_or_else(|| anchor.inputs.clone()) }
            else {
                let mut inputs = anchor.inputs.clone();
                for input in supplied.into_iter().flatten() {
                    if direct.is_some() {
                        add_direct_delivery_input(arch,source,&mut inputs,&input)?;
                    } else {
                        add_input(arch,source,&mut inputs,input.input.storage.address(arch)?,input.input.size)?;
                    }
                }
                inputs
            };
        for target in targets.iter().skip(1) {
            if let Some(target) = function_indices.get(target).map(|&index| &spec.functions[index]) {
                for input in &target.inputs { add_input(arch,source,&mut inputs,input.storage.address(arch)?,input.size)?; }
            }
        }
        spec.calls.push(ExportCallSpec { key, direct, targets, inputs, helper: String::new() });
    }
    // Refinement is dependency-driven, not another all-roots round. Each
    // positive candidate can only shrink in its finite byte-width/removal
    // domain. A changed callee requeues only actual bound callers, including
    // cycles; no arbitrary iteration cap or retained Funcdata is needed.
    let mut provisional = ExportBinding::from_spec_with_sources(arch, &spec,selected,&sources)?;
    let entries: BTreeMap<_,_> = selected.iter().map(|entry| (ExportAddress::new(&entry.entry),entry)).collect();
    let mut uses = BTreeMap::<ExportAddress,BTreeSet<usize>>::new();
    for (index,call) in spec.calls.iter_mut().enumerate() {
        call.helper = provisional.calls[&call.key].helper.clone();
        for target in &call.targets { uses.entry(target.clone()).or_default().insert(index); }
    }
    let mut queued: BTreeSet<_> = spec.functions.iter().map(|function| function.entry.clone()).collect();
    let mut queue: VecDeque<_> = queued.iter().cloned().collect();
    let mut failed: BTreeSet<_> = spec.failures.iter().map(|(entry,_)| entry.clone()).collect();
    while let Some(key) = queue.pop_front() {
        queued.remove(&key);
        if failed.contains(&key) { continue; }
        let function = &provisional.functions[&key];
        let retained = match analyze(arch,entries[&key],Some(&function.working),Some(&provisional))
            .and_then(|fd| refine_inputs(arch,&fd,&geometries[&key],&function.spec.inputs,omitted.get(&key)))
        {
            Ok(inputs) => inputs,
            Err(error @ KunaError::Transport { .. }) => return Err(error),
            Err(error) => {
                failed.insert(key.clone());
                spec.failures.push((key,error.to_string()));
                continue;
            }
        };
        if retained == function.spec.inputs { continue; }
        spec.functions[function_indices[&key]].inputs = retained.clone();
        provisional.refine_function(arch,&key,&retained)?;
        for &index in uses.get(&key).into_iter().flatten() {
            let call = &mut spec.calls[index];
            // Authored sites are never reseeded. Ordinary calls retain every
            // supplied operand once. A proven unsigned low-view delivery need
            // not import unused upper bytes of that same integer operand.
            if supplied_calls.get(&call.key).is_some_and(|(_,authored)| *authored) { continue; }
            let anchor = &call.targets[0];
            let mut inputs = provisional.functions[anchor].spec.inputs.clone();
            for target in call.targets.iter().skip(1) {
                for input in &provisional.functions[target].spec.inputs {
                    add_input(arch,&geometries[anchor],&mut inputs,input.storage.address(arch)?,input.size)?;
                }
            }
            if let Some((supplied,_)) = supplied_calls.get(&call.key) {
                for input in supplied {
                    if call.direct.is_some() {
                        add_direct_delivery_input(arch,&geometries[anchor],&mut inputs,input)?;
                    } else {
                        add_input(arch,&geometries[anchor],&mut inputs,input.input.storage.address(arch)?,input.input.size)?;
                    }
                }
            }
            if inputs == call.inputs { continue; }
            call.inputs = inputs;
            provisional.refine_call(arch,&call.key,&call.inputs)?;
            if function_indices.contains_key(&call.key.caller) && queued.insert(call.key.caller.clone()) {
                queue.push_back(call.key.caller.clone());
            }
        }
    }
    let mut reserved: BTreeSet<String> = arch.print().reserved_identifiers().map(|names| names.as_ref().clone()).unwrap_or_default();
    reserved.extend(selected.iter().map(|entry| entry.name.clone()));
    for function in &mut spec.functions {
        let source = &geometries[&function.entry];
        function.private = differs(function.inputs.iter(),source);
        function.wrapper = function.private && function.inputs.iter().all(|input| input.source_slot >= 0);
        if function.wrapper {
            let base = format!("kuna_impl_{}",identifier(&function.name));
            let mut name = base.clone();
            let mut suffix = 1;
            while !reserved.insert(name.clone()) { suffix += 1; name = format!("{base}_{suffix}"); }
            function.implementation = name;
        }
    }
    // New direct adapters support exact carrier occurrences, not interior
    // byte extraction. Unsupported sites retain ordinary diagnostic emission.
    spec.calls.retain(|call| call.direct.as_ref().is_none_or(|target|
        spec.functions[function_indices[target]].inputs.iter().all(|required|
            call.inputs.iter().any(|available|
                available.storage == required.storage && available.size == required.size))));
    ExportBinding::from_spec_with_sources(arch,&spec,selected,&sources)
}
fn covers(input:&ExportInputSpec,address:&Address,size:i32) -> bool {
    size > 0 && address.get_space().is_some_and(|space| input.storage.space == space.get_name())
        && input.storage.offset == address.get_offset() && input.size >= size
}
fn output_disjoint(proto:&FuncProto,address:&Address,size:i32) -> bool {
    let output = proto.get_output();
    if output.get_type().is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_VOID) { return true; }
    let at = output.get_address();
    !at.is_invalid() && (at.get_space().map(|space| space.get_index()) != address.get_space().map(|space| space.get_index())
        || at.get_offset().saturating_add(output.get_size().max(0) as u64) <= address.get_offset()
        || address.get_offset().saturating_add(size.max(0) as u64) <= at.get_offset())
}
/// Completed physical occurrences, not source arity or operand value addresses.
/// Unsupported models, storage or demanded results keep their ordinary path.
#[derive(Clone)]
struct FinalizedInput {
    input: ExportInputSpec,
    integer_value: bool,
}

fn finalized_inputs(fd:&Funcdata,index:i32,source:&FuncProto) -> Option<Vec<FinalizedInput>> {
    let call = fd.get_call_specs(index);
    let operation = fd.obank().get(call.get_op())?;
    let proto = call.proto();
    let storage = call.final_input_storage();
    if !proto.has_model() || !proto.has_store() || call.get_paramshift() != 0
        || !proto.model().is_compatible(source.model())
        || proto.get_extra_pop() != source.get_extra_pop()
        || storage.len()+1 != operation.num_input() as usize { return None; }
    if storage.iter().enumerate().any(|(slot,(at,size))| storage[..slot].iter().any(|(other,width)|
        at.get_space().map(|s| s.get_index()) == other.get_space().map(|s| s.get_index())
            && at.get_offset() < other.get_offset().saturating_add(*width as u64)
            && other.get_offset() < at.get_offset().saturating_add(*size as u64))) { return None; }
    if let Some(output) = operation.get_out().and_then(|id| fd.vbank().get(id)) {
        let actual = proto.get_output();
        let target = source.get_output();
        if output.get_size() != target.get_size()
            || actual.get_address() != target.get_address() || actual.get_size() != target.get_size()
            || !actual.get_type().zip(target.get_type()).is_some_and(|(a,b)|
                Rc::ptr_eq(a,b) && matches!(b.get_metatype(),
                    type_metatype::TYPE_INT|type_metatype::TYPE_UINT|type_metatype::TYPE_BOOL|type_metatype::TYPE_PTR))
        { return None; }
    }
    storage.iter().enumerate().map(|(slot,(address,size))| {
        if !matches!(size,1|2|4|8) || !address.get_space().is_some_and(|space|
            space.get_name() == "register") { return None; }
        let value_id = operation.get_in(slot as i32+1)?;
        let value = fd.vbank().get(value_id)?;
        if value.get_size() != *size { return None; }
        // Match the actual expression type consumed by op_export_call_ir.
        // A destination UINT carrier alone cannot justify narrowing a pointer,
        // float, Boolean or unknown expression with an ordinary numeric cast.
        let emitted_type = crate::printc::declared_variable_type(fd,fd.get_arch().decl_high_type,value_id)
            .unwrap_or_else(|| Rc::clone(value.get_type()));
        let integer_value = emitted_type.get_size() == *size
            && matches!(emitted_type.get_metatype(),type_metatype::TYPE_INT|type_metatype::TYPE_UINT);
        let source_slot = (0..source.num_params()).find(|&slot| source.get_param(slot).is_some_and(|p|
            p.get_address() == *address && p.get_size() == *size
                && p.get_type().is_some_and(|ty| Rc::ptr_eq(ty,value.get_type()))));
        Some(FinalizedInput { input:ExportInputSpec { storage:ExportAddress::new(address),size:*size,
            source_slot:source_slot.unwrap_or(-1),unsigned:source_slot.is_none()
                || value.get_type().get_metatype() == type_metatype::TYPE_BOOL,
            name:format!("kuna_value{slot}") }, integer_value })
    }).collect()
}
fn refine_inputs(
    arch:&Architecture,fd:&Funcdata,source:&FuncProto,inputs:&[ExportInputSpec],
    omitted:Option<&BTreeSet<i32>>,
) -> KunaResult<Vec<ExportInputSpec>> {
    let mut observed = BTreeMap::new();
    for value in fd.vbank().iter_loc().filter_map(|id| fd.vbank().get(id)) {
        if !value.is_input() || value.has_no_descend()
            || !value.descend_iter().any(|id| fd.obank().get(id).is_some_and(|op| !op.is_dead()))
        {
            continue;
        }
        let Some(address) = native_address(value.get_addr()) else { continue; };
        let bits = value.get_consume() & kuna_base::address::calc_mask(value.get_size());
        *observed.entry((address,value.get_size())).or_insert(0u64) |= bits;
    }
    let mut retained = Vec::with_capacity(inputs.len());
    for input in inputs {
        let address = input.storage.address(arch)?;
        let bits = observed.get(&(native_address(&address).expect("registered export input"),input.size))
            .copied().unwrap_or(0);
        let used = (u64::BITS - bits.leading_zeros()).div_ceil(8);
        let used = if used == 0 { 0 } else { used.next_power_of_two() as i32 };
        let source_width = source.get_param(input.source_slot).map_or(0,|parameter| parameter.get_size());
        if used == 0 && (input.source_slot < 0
            || omitted.is_some_and(|slots| slots.contains(&input.source_slot))) { continue; }
        let width = used.max(source_width).max(1);
        let mut input = input.clone();
        if width < input.size && matches!(width,1|2|4|8) {
            if let Some(entry) = source.model().input().get_entry().iter()
                .find(|entry| entry.get_type() == type_class::TYPECLASS_GENERAL
                    && entry.justified_contain(&address,input.size) == 0)
            {
                let mut slot = entry.get_slot(&address,0) - entry.get_group();
                let narrowed = entry.get_addr_by_slot(&mut slot,width,1,arch.manage())?;
                if !narrowed.is_invalid() {
                    input.storage = ExportAddress::new(&narrowed);
                    input.size = width;
                    input.unsigned = true;
                }
            }
        }
        retained.push(input);
    }
    Ok(retained)
}
fn differs<'a>(inputs:impl ExactSizeIterator<Item=&'a ExportInputSpec>, source:&FuncProto) -> bool {
    inputs.len() != source.num_params() as usize || inputs.enumerate().any(|(slot,input)| {
        input.unsigned || source.get_param(slot as i32).is_none_or(|p|
            input.source_slot != slot as i32 || input.size != p.get_size() || input.storage != ExportAddress::new(&p.get_address()))
    })
}
fn same_signature(left:&FuncProto,right:&FuncProto) -> bool {
    let same = |left:Option<&Rc<Datatype>>,right:Option<&Rc<Datatype>>| match (left,right) {
        (Some(left),Some(right)) => Rc::ptr_eq(left,right) || left.type_order(right).is_ok_and(|order| order == 0),
        (None,None) => true,
        _ => false,
    };
    left.has_model() && right.has_model() && left.get_model_name() == right.get_model_name()
        && left.num_params() == right.num_params() && left.is_dotdotdot() == right.is_dotdotdot()
        && same(left.get_output_type(),right.get_output_type())
        && (0..left.num_params()).all(|slot| same(left.get_param(slot).and_then(|p| p.get_type()),
            right.get_param(slot).and_then(|p| p.get_type())))
}
fn source_compatible_code(code:&Datatype,source:&FuncProto) -> bool {
    let ready = |dtype:&Rc<Datatype>| !dtype.is_incomplete() || dtype.get_ptr_to().is_some();
    !code.is_incomplete() && code.get_code_prototype().is_some_and(|proto|
        proto.has_model() && proto.has_store() && !source_diagnostic(proto)
            && proto.get_output_type().zip(source.get_output_type())
                .is_some_and(|(left,right)| ready(left) && Rc::ptr_eq(left,right))
            && same_signature(proto,source)
            // Structural equality alone can conflate distinct nominal records.
            // A different reference safely rebuilds from the source declaration.
            && (0..proto.num_params()).all(|slot|
                proto.get_param(slot).and_then(|parameter| parameter.get_type())
                    .zip(source.get_param(slot).and_then(|parameter| parameter.get_type()))
                    .is_some_and(|(left,right)| ready(left) && Rc::ptr_eq(left,right))))
}
/// Keep the existing entry extension as the producer of a wider read. This
/// projects only a dependency, not the raw probe's physical range. In
/// particular, a word extension cannot account for unknown bytes above it.
fn modeled_extension_contains(
    rule:Option<crate::kuna_narrowext::Widen>,list:&crate::fspec::ParamListStandard,
    address:&Address,size:i32,ty:&Datatype,required:&Address,required_size:i32,
) -> bool {
    let mut container = kuna_num::pcoderaw::VarnodeData::default();
    let (opcode,_) = crate::kuna_narrowext::or_model(rule,list,address,size,Some(ty),&mut container);
    matches!(opcode,OpCode::CPUI_INT_ZEXT|OpCode::CPUI_INT_SEXT|OpCode::CPUI_PIECE)
        && container.get_addr().justified_contain(container.size as i32,required,required_size,false) >= 0
}
/// Retain a selected implementation's proven unsigned low-view requirement
/// when the actual containing operand has the same-width integer expression
/// consumed by the emitter. All other supplied occurrences use normal merging.
fn add_direct_delivery_input(arch:&Architecture, source:&FuncProto, inputs:&mut Vec<ExportInputSpec>, supplied:&FinalizedInput) -> KunaResult<()> {
    let address = supplied.input.storage.address(arch)?;
    let size = supplied.input.size;
    if supplied.integer_value && matches!(size,1|2|4|8) {
        let space = address.get_space().map(|space| space.get_name());
        let end = address.get_offset().saturating_add(size as u64);
        let mut overlaps = inputs.iter().filter(|input|
            input.size > 0 && space == Some(input.storage.space.as_str())
                && input.storage.offset < end
                && address.get_offset() < input.storage.offset.saturating_add(input.size as u64));
        if let Some(required) = overlaps.next() {
            if overlaps.next().is_none() && required.unsigned && required.size < size
                && matches!(required.size,1|2|4|8)
                && address.justified_contain(size,&required.storage.address(arch)?,required.size,false) == 0
            {
                return Ok(());
            }
        }
    }
    add_input(arch,source,inputs,address,size)
}

fn add_input(arch:&Architecture, source:&FuncProto, inputs:&mut Vec<ExportInputSpec>, address:Address, size:i32) -> KunaResult<()> {
    if size <= 0 || size > 8 || !matches!(size,1|2|4|8) { return Ok(()); }
    let entries = source.model().input().get_entry();
    let Some(entry_index) = entries.iter().position(|entry| entry.get_type() == type_class::TYPECLASS_GENERAL
        && entry.get_space().get_name() == "register" && size >= entry.get_min_size() && size <= entry.get_size()
        && entry.justified_contain(&address,size) == 0) else { return Ok(()) };
    if let Some(existing) = inputs.iter_mut().find(|input| input.storage.address(arch).is_ok_and(|at|
        at.justified_contain(input.size,&address,size,false) >= 0 || address.justified_contain(size,&at,input.size,false) >= 0)) {
        if size > existing.size {
            let current = existing.storage.address(arch)?;
            // Only an unchanged source occurrence can retain its modeled
            // producer. Never infer source geometry for an ambient or already
            // widened carrier. Use exactly with_inputs' working datatype:
            // a Boolean raw byte remains UINT, not a normalized Boolean.
            if existing.source_slot >= 0 {
                if let Some(parameter) = source.get_param(existing.source_slot)
                    .filter(|parameter| parameter.get_size() == existing.size
                        && parameter.get_address() == current)
                {
                    let ty = if existing.unsigned {
                        Some(arch.types().get_base(existing.size,type_metatype::TYPE_UINT)?)
                    } else { parameter.get_type().cloned() };
                    if ty.as_ref().is_some_and(|ty| modeled_extension_contains(
                        crate::kuna_narrowext::rules(arch).input,source.model().input(),
                        &current,existing.size,ty,&address,size,
                    )) { return Ok(()); }
                }
            }
            existing.storage = ExportAddress::new(&address);
            existing.size = size;
            existing.unsigned = true;
        }
        return Ok(());
    }
    let base = format!("kuna_arg{entry_index}");
    let mut name = base.clone();
    let mut suffix = 1;
    while inputs.iter().any(|input| input.name == name) {
        suffix += 1;
        name = format!("{base}_{suffix}");
    }
    inputs.push(ExportInputSpec { storage: ExportAddress::new(&address), size, source_slot: -1, unsigned:true, name });
    inputs.sort_by_key(|input| input.storage.address(arch).ok().and_then(|address|
        entries.iter().position(|entry| entry.justified_contain(&address,input.size) == 0)).unwrap_or(usize::MAX));
    Ok(())
}
fn analyze(arch:&mut Architecture, entry:&ExportEntry, proto:Option<&FuncProto>, binding:Option<&ExportBinding>) -> KunaResult<Funcdata> {
    let saved_model = arch.kuna_pending_proto_model.clone();
    arch.kuna_pending_proto_model = entry.seed.model.clone().or_else(|| saved_model.clone());
    let result = crate::decompile_drive::decompile_func_full_with_export_working(arch,&entry.name,entry.entry.clone(),entry.size,
        &[],&[],&[],entry.seed.pending_proto.as_ref(),&entry.seed.flow_overrides,&[],&entry.seed.mapped_params,None,&[],proto,binding);
    arch.kuna_pending_proto_model = saved_model;
    result
}

fn effective_source(arch:&Architecture,entry:&ExportEntry) -> KunaResult<(Rc<FuncProto>,bool)> {
    let mut fd = arch.new_funcdata(&entry.name,entry.entry.clone(),entry.size)?;
    let declared = crate::decompile_drive::initialize_source_prototype(
        arch,&mut fd,entry.seed.pending_proto.as_ref(),
        entry.seed.model.clone().or_else(|| arch.kuna_pending_proto_model.clone()),&[],
    )?;
    if !declared && entry.seed.pending_proto.is_none() {
        if let Some((at,pieces)) = &arch.elfmain_main_decl {
            if at.get_offset() == entry.entry.get_offset() {
                if let Some(model) = arch.default_fp() {
                    if let Some(runtime) = crate::kuna_elfmaindecl::Runtime::new(pieces,model,arch.types(),arch.manage()) {
                        fd.apply_locked_prototype_with_model(&runtime.output,None)?;
                        fd.get_func_proto_mut().set_input_lock(false);
                    }
                }
            }
        }
    }
    fd.apply_mapped_params(&entry.seed.mapped_params);
    let mut source = FuncProto::new();
    source.copy(fd.get_func_proto());
    Ok((arch.types_impl().retain_source_proto(Rc::new(source)),
        fd.get_override().has_authored_proto_overrides()))
}
