use super::*;
use kuna_base::marshal::*;
use crate::dtype::TypeFactoryImpl;
use crate::remote_provider::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PrototypeEncoding { Internal, LocalDbEntry, LogicalCallable }
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PrototypeDecoding { LogicalCallable, PhysicalEntry }
const PARAM: ElementId = ElementId::new("param", 166);
const RETPARAM: ElementId = ElementId::new("retparam", 171);

impl FuncProto {
    pub fn sanitize_source_names(&mut self, mode: crate::kuna_symbolnamechars::NameChars) {
        if let Some(pieces) = &mut self.logical {
            if let std::borrow::Cow::Owned(name) = crate::kuna_symbolnamechars::sanitize_symbol_name(&pieces.name, mode) { pieces.name = name; }
            for name in &mut pieces.innames {
                if let std::borrow::Cow::Owned(cleaned) = crate::kuna_symbolnamechars::sanitize_symbol_name(name, mode) { *name = cleaned; }
            }
        }
        if let Some(store) = &mut self.store {
            for i in 0..store.get_num_inputs() {
                let Some(param) = store.get_input(i) else { continue };
                let std::borrow::Cow::Owned(name) = crate::kuna_symbolnamechars::sanitize_symbol_name(param.get_name(), mode) else { continue };
                let piece = ParameterPieces { addr: param.get_address(), type_: param.get_type().cloned(), flags: param.get_flags() };
                let usepoint = param.get_usepoint();
                store.set_input(i, &name, &piece);
                if let Some(param) = store.get_input_mut(i) { param.set_usepoint(usepoint); }
            }
        }
    }
    pub fn from_logical(pieces: &PrototypePieces, model: Rc<ProtoModel>, factory: &dyn TypeFactory) -> KunaResult<Self> {
        let mut result = Self::new();
        result.set_internal(model, factory.get_type_void()?);
        result.logical = Some(pieces.clone());
        if pieces.output_storage.as_ref().is_some_and(|p| p.flags & parameter_pieces_flags::CUSTOM_STORAGE != 0)
            || pieces.input_storage.iter().any(|(_, p)| p.flags & parameter_pieces_flags::CUSTOM_STORAGE != 0) {
            result.flags |= func_proto_flags::CUSTOM_STORAGE;
        }
        result.first_var_arg_slot = Some(pieces.first_var_arg_slot);
        result.set_dotdotdot(pieces.first_var_arg_slot >= 0);
        result.set_output(&pieces.output_storage.clone().unwrap_or(ParameterPieces {
            addr: Address::new_invalid(), type_: Some(pieces.outtype.clone().unwrap_or(factory.get_type_void()?)),
            flags: if pieces.outtype.is_some() { parameter_pieces_flags::TYPELOCK } else { 0 },
        }));
        for (i, ty) in pieces.intypes.iter().enumerate() {
            result.set_param(i as int4, pieces.innames.get(i).map(String::as_str).unwrap_or(""), &ParameterPieces {
                addr: Address::new_invalid(), type_: Some(Rc::clone(ty)), flags: parameter_pieces_flags::TYPELOCK | if pieces.innames.get(i).is_some_and(|n| !n.is_empty()) { parameter_pieces_flags::NAMELOCK } else { 0 },
            });
        }
        for (slot, piece) in &pieces.input_storage {
            result.set_param(*slot, pieces.innames.get(*slot as usize).map(String::as_str).unwrap_or(""), piece);
        }
        result.set_input_lock(true);
        result.set_model_lock(true);
        Ok(result)
    }

    pub(crate) fn retain_resolved_dependencies(&self) {
        let mut roots = Vec::new();
        if self.has_store() {
            if let Some(t) = self.get_output_type() { roots.push(Rc::clone(t)); }
            for i in 0..self.num_params() {
                if let Some(t) = self.get_param(i).and_then(|p| p.get_type()) { roots.push(Rc::clone(t)); }
            }
        }
        let mut seen = std::collections::HashSet::new();
        let mut retained = self.resolved_dependencies.borrow_mut();
        retained.clear();
        for root in roots {
            for dependency in Datatype::resolved_dependencies(&root) {
                if seen.insert(Rc::as_ptr(&dependency)) { retained.push(dependency); }
            }
        }
    }
    pub(crate) fn clear_reader_dependencies(&self) {
        self.resolved_dependencies.borrow_mut().clear();
    }

    pub(crate) fn logical_pieces(&self) -> Option<&PrototypePieces> { self.logical.as_ref() }
    pub(crate) fn get_first_var_arg_slot(&self) -> int4 {
        self.first_var_arg_slot.unwrap_or(if self.is_dotdotdot() { self.num_params() } else { -1 })
    }
    /// Retain the authored declaration after its independent working seed succeeds.
    pub(crate) fn retain_logical_declaration(&mut self, pieces: &PrototypePieces) {
        self.logical = Some(pieces.clone());
    }
    /// The `updateAllTypes` diagnostic state, confined to declaration application.
    pub(crate) fn record_source_assignment_refusal(&mut self) {
        let genuine_void = self.get_output_type()
            .is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_VOID);
        let input_locked = genuine_void && self.num_params() == 0 && self.is_input_locked();
        let output_locked = genuine_void && self.is_output_locked();
        let model_locked = self.is_model_locked();
        self.store_mut().clear_all_inputs();
        self.store_mut().clear_output();
        self.logical = None;
        self.flags &= !func_proto_flags::VOIDINPUTLOCK;
        self.set_input_errors(true);
        self.set_input_lock(input_locked);
        self.set_output_lock(output_locked);
        self.set_model_lock(model_locked);
    }
    /// Extend a proven generated open prefix without replacing independent facts.
    pub(crate) fn append_generated_inputs(&mut self, allocated: &FuncProto) {
        for slot in self.num_params()..allocated.num_params() {
            if let Some(parameter) = allocated.get_param(slot) {
                self.set_param(slot, parameter.get_name(), &ParameterPieces {
                    addr: parameter.get_address(), type_: parameter.get_type().cloned(), flags: parameter.get_flags(),
                });
                self.set_param_usepoint(slot, parameter.get_usepoint());
            }
        }
        self.logical = None;
        self.first_var_arg_slot = Some(-1);
        self.flags &= !func_proto_flags::VOIDINPUTLOCK;
        self.set_dotdotdot(false);
    }
    /// Preserve a logical callable's declaration while leaving raw storage absent.
    /// Supplied physical entries use independent physical completion instead.
    fn retain_missing_storage_declaration(&mut self) {
        let missing_output = self.get_output_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID)
            && self.get_output().get_address().is_invalid();
        if !missing_output && !(0..self.num_params()).any(|i|
            self.get_param(i).is_some_and(|parameter| parameter.get_address().is_invalid()))
        {
            return;
        }
        let mut pieces = PrototypePieces::default();
        pieces.outtype = self.get_output_type().cloned();
        for i in 0..self.num_params() {
            let Some(parameter) = self.get_param(i) else { continue };
            if !parameter.get_address().is_invalid() {
                pieces.input_storage.push((i, ParameterPieces {
                    addr: parameter.get_address(), type_: parameter.get_type().cloned(), flags: parameter.get_flags(),
                }));
            }
            if parameter.is_hidden_return() { continue; }
            if let Some(ty) = parameter.get_type() {
                pieces.intypes.push(Rc::clone(ty));
                pieces.innames.push(parameter.get_name().to_owned());
            }
        }
        pieces.first_var_arg_slot = self.first_var_arg_slot.unwrap_or(
            if self.is_dotdotdot() { pieces.intypes.len() as int4 } else { -1 });
        let output = self.get_output();
        if !output.get_address().is_invalid() {
            pieces.output_storage = Some(ParameterPieces {
                addr: output.get_address(), type_: output.get_type().cloned(), flags: output.get_flags(),
            });
        }
        self.logical = Some(pieces);
    }
    pub(crate) fn retain_mapped_declaration_input(
        &mut self,physical_slot:int4,source_slot:usize,name:&str,piece:&ParameterPieces,
    ) {
        let Some(logical) = self.logical.as_mut() else { return; };
        // A mapped physical slot need not correspond to an authored formal.
        // Preserve sparse storage without turning intervening holes into inputs.
        if let (Some(formal), Some(ty)) = (logical.intypes.get_mut(source_slot), piece.type_.as_ref()) {
            *formal = Rc::clone(ty);
            logical.innames.resize(logical.intypes.len(),String::new());
            logical.innames[source_slot] = name.to_owned();
        }
        logical.input_storage.retain(|(slot,_)| *slot != physical_slot);
        logical.input_storage.push((physical_slot,piece.clone()));
    }
    pub(crate) fn decoded_inject_name(&self) -> Option<&str> { self.inject_name.as_deref() }
    pub(crate) fn declared_model_name(&self) -> &str { &self.declared_model }
    pub fn supplied_extra_pop(&self) -> Option<int4> { self.supplied_extrapop.then_some(self.extrapop) }

    pub fn decode_wire(decoder: &mut dyn Decoder, types: &TypeFactoryImpl, context: PrototypeDecoding) -> KunaResult<Self> {
        let id = decoder.open_element_id(&ELEM_PROTOTYPE)?;
        let mut model = String::new();
        let mut flags = 0;
        let mut extrapop = None;
        loop {
            let attr = decoder.get_next_attribute_id()?;
            if attr == 0 { break; }
            if attr == ATTRIB_MODEL.get_id() { model = String::from_utf8_lossy(&decoder.read_string()?).into_owned(); }
            else if attr == crate::remote_provider::ATTRIB_EXTRAPOP.get_id() { extrapop = Some(decoder.read_signed_integer_expect_string(b"unknown", EXTRAPOP_UNKNOWN as i64)? as int4); }
            else {
                let bit = if attr == ATTRIB_MODELLOCK.get_id() { func_proto_flags::MODELLOCK }
                else if attr == ATTRIB_DOTDOTDOT.get_id() { func_proto_flags::DOTDOTDOT }
                else if attr == ATTRIB_VOIDLOCK.get_id() { func_proto_flags::VOIDINPUTLOCK }
                else if attr == ATTRIB_INLINE.get_id() { func_proto_flags::IS_INLINE }
                else if attr == ATTRIB_NORETURN.get_id() { func_proto_flags::NO_RETURN }
                else if attr == ATTRIB_CUSTOM.get_id() { func_proto_flags::CUSTOM_STORAGE }
                else if attr == ATTRIB_CONSTRUCTOR.get_id() { func_proto_flags::IS_CONSTRUCTOR }
                else if attr == ATTRIB_DESTRUCTOR.get_id() { func_proto_flags::IS_DESTRUCTOR } else { 0 };
                if bit != 0 && decoder.read_bool()? { flags |= bit; }
            }
        }
        let mut result = Self::new();
        result.attach_internal_store(types.get_type_void()?);
        result.declared_model = model.clone();
        if context == PrototypeDecoding::LogicalCallable {
            result.set_model(Some(types.resolve_supplied_proto_model(&model)?));
        }
        result.flags |= flags;
        if let Some(value) = extrapop { result.extrapop = value; result.supplied_extrapop = true; }
        let mut saw_output = false;
        while decoder.peek_element()? != 0 {
            let child = decoder.peek_element()?;
            if child == ELEM_RETURNSYM.get_id() {
                let (name, piece) = decode_parameter(decoder, types)?;
                let _ = name;
                result.set_output(&piece);
                saw_output = true;
            } else if child == ELEM_INTERNALLIST.get_id() {
                let list = decoder.open_element()?;
                loop {
                    let attr = decoder.get_next_attribute_id()?;
                    if attr == 0 { break; }
                    if attr == kuna_base::address::ATTRIB_FIRST.get_id() {
                        result.first_var_arg_slot = Some(decoder.read_signed_integer()? as int4);
                    }
                }
                while decoder.peek_element()? != 0 {
                    let is_return = decoder.peek_element()? == RETPARAM.get_id();
                    let (name, piece) = decode_parameter(decoder, types)?;
                    if is_return { result.set_output(&piece); saw_output = true; }
                    else { result.set_param(result.num_params(), &name, &piece); }
                }
                decoder.close_element(list)?;
            } else if child == ELEM_UNAFFECTED.get_id() || child == ELEM_KILLEDBYCALL.get_id() || child == ELEM_RETURNADDRESS.get_id() || child == ELEM_LIKELYTRASH.get_id() {
                let list = decoder.open_element()?;
                while decoder.peek_element()? != 0 {
                    let (addr, size) = Address::decode_sized(decoder)?;
                    if child == ELEM_LIKELYTRASH.get_id() {
                        result.likelytrash.push(VarnodeData { space: addr.get_space().cloned(), offset: addr.get_offset(), size: size as u32 });
                    } else {
                        let effect = if child == ELEM_UNAFFECTED.get_id() { effect_type::UNAFFECTED } else if child == ELEM_KILLEDBYCALL.get_id() { effect_type::KILLEDBYCALL } else { effect_type::RETURN_ADDRESS };
                        result.effectlist.push(EffectRecord::from_varnode(VarnodeData {
                            space: addr.get_space().cloned(), offset: addr.get_offset(), size: size as u32,
                        }, effect));
                    }
                }
                decoder.close_element(list)?;
            } else if child == crate::pcodeinject::ELEM_INJECT.get_id() {
                let inject = decoder.open_element()?;
                result.inject_name = Some(String::from_utf8_lossy(&decoder.read_string_id(&ATTRIB_CONTENT)?).into_owned());
                result.flags |= func_proto_flags::IS_INLINE;
                decoder.close_element(inject)?;
            } else { let unknown = decoder.open_element()?; decoder.close_element_skipping(unknown)?; }
        }
        decoder.close_element(id)?;
        if !saw_output { return Err(KunaError::decoder("Missing <returnsym> tag")); }
        if result.is_input_locked() || result.is_output_locked() { result.set_model_lock(true); }
        result.effectlist.sort_by(|a,b| a.get_address().cmp(&b.get_address()));
        result.likelytrash.sort();
        if context == PrototypeDecoding::LogicalCallable {
            result.retain_missing_storage_declaration();
        }
        if result.has_model() { result.complete_decoded_effects()?; }
        Ok(result)
    }

    pub(crate) fn complete_decoded_effects(&mut self) -> KunaResult<()> {
        if !self.effectlist.is_empty() {
            let overrides = std::mem::take(&mut self.effectlist);
            self.effectlist = self.model().effect_list().to_vec();
            let original_len = self.effectlist.len();
            for effect in overrides {
                let matched = ProtoModel::lookup_record(&self.effectlist, original_len as int4, &effect.get_address(), effect.get_size());
                if matched == -2 { return Err(KunaError::lowlevel("Partial overlap of prototype override with existing effects")); }
                if matched >= 0 { self.effectlist[matched as usize] = effect; } else { self.effectlist.push(effect); }
            }
            self.effectlist.sort_by(|a,b| a.get_address().cmp(&b.get_address()));
        }
        if !self.likelytrash.is_empty() {
            let model_trash = self.model().trash_list().to_vec();
            self.likelytrash.extend(model_trash);
            self.likelytrash.sort(); self.likelytrash.dedup();
        }
        Ok(())
    }

    pub(super) fn encode_internal(&self, encoder: &mut dyn Encoder, logical: Option<&PrototypePieces>) -> KunaResult<()> {
        encoder.open_element(&ELEM_INTERNALLIST);
        if let Some(first) = self.first_var_arg_slot.filter(|first| *first >= 0) {
            encoder.write_signed_integer(&kuna_base::address::ATTRIB_FIRST, first as i64);
        }
        if let Some(logical) = logical {
            let output = logical.outtype.as_ref().or_else(|| logical.output_storage.as_ref().and_then(|p| p.type_.as_ref())).or_else(|| self.get_output_type());
            let source_flags = |flags| flags & !(parameter_pieces_flags::INDIRECTSTORAGE | parameter_pieces_flags::HIDDENRETPARM);
            encode_parameter_parts(encoder, &RETPARAM, "", &Address::new_invalid(), output, source_flags(self.get_output().get_flags()))?;
            let mut parameters = (0..self.num_params()).filter_map(|i| self.get_param(i)).filter(|p| !p.is_hidden_return());
            for (slot, ty) in logical.intypes.iter().enumerate() {
                let flags = parameters.next().map_or(0, |p| source_flags(p.get_flags()));
                encode_parameter_parts(encoder, &PARAM, logical.innames.get(slot).map(String::as_str).unwrap_or(""), &Address::new_invalid(), Some(ty), flags)?;
            }
        } else {
            encode_parameter(encoder, &RETPARAM, self.get_output())?;
            for i in 0..self.num_params() {
                if let Some(param) = self.get_param(i) { encode_parameter(encoder, &PARAM, param)?; }
            }
        }
        encoder.close_element(&ELEM_INTERNALLIST);
        Ok(())
    }
}

fn decode_parameter(decoder: &mut dyn Decoder, types: &TypeFactoryImpl) -> KunaResult<(String, ParameterPieces)> {
    let id = decoder.open_element()?;
    let mut name = String::new();
    let mut flags = 0;
    loop {
        let attr = decoder.get_next_attribute_id()?;
        if attr == 0 { break; }
        if attr == ATTRIB_NAME.get_id() { name = String::from_utf8_lossy(&decoder.read_string()?).into_owned(); continue; }
        let bit = if attr == ATTRIB_TYPELOCK.get_id() { parameter_pieces_flags::TYPELOCK }
        else if attr == ATTRIB_NAMELOCK.get_id() { parameter_pieces_flags::NAMELOCK }
        else if attr == ATTRIB_THISPTR.get_id() { parameter_pieces_flags::ISTHIS }
        else if attr == ATTRIB_INDIRECTSTORAGE.get_id() { parameter_pieces_flags::INDIRECTSTORAGE }
        else if attr == ATTRIB_HIDDENRETPARM.get_id() { parameter_pieces_flags::HIDDENRETPARM } else { 0 };
        if bit != 0 && decoder.read_bool()? { flags |= bit; }
    }
    let addr = Address::decode(decoder)?;
    let type_ = Some(types.decode_type(decoder)?);
    decoder.close_element(id)?;
    Ok((name, ParameterPieces { addr, type_, flags }))
}
fn encode_parameter(encoder: &mut dyn Encoder, id: &ElementId, p: &dyn ProtoParameter) -> KunaResult<()> {
    encode_parameter_parts(encoder, id, p.get_name(), &p.get_address(), p.get_type(), p.get_flags())
}
fn encode_parameter_parts(encoder: &mut dyn Encoder, id: &ElementId, name: &str, address: &Address, ty: Option<&Rc<Datatype>>, flags: uint4) -> KunaResult<()> {
    encoder.open_element(id);
    if !name.is_empty() { encoder.write_string(&ATTRIB_NAME, name.as_bytes()); }
    for (attr, bit) in [(&ATTRIB_TYPELOCK,parameter_pieces_flags::TYPELOCK),(&ATTRIB_NAMELOCK,parameter_pieces_flags::NAMELOCK),(&ATTRIB_THISPTR,parameter_pieces_flags::ISTHIS),(&ATTRIB_INDIRECTSTORAGE,parameter_pieces_flags::INDIRECTSTORAGE),(&ATTRIB_HIDDENRETPARM,parameter_pieces_flags::HIDDENRETPARM)] { if flags & bit != 0 { encoder.write_bool(attr,true); } }
    address.encode(encoder)?;
    if let Some(ty) = ty { ty.encode_ref(encoder)?; }
    encoder.close_element(id);
    Ok(())
}
