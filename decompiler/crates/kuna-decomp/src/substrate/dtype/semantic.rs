use super::*;
use crate::fspec::{FuncProto, PrototypePieces};

/// Independent semantic ownership for a held callable, without changing raw shells.
#[derive(Clone)]
pub struct CallableReader {
    state: Rc<CallableReaderState>,
}

pub(super) struct CallableReaderState {
    datatype: Rc<Datatype>,
    dependencies: RefCell<Vec<Rc<Datatype>>>,
}

pub(super) struct CodeDecodeGuard<'a> {
    factory: &'a TypeFactoryImpl,
    key: (String, u64),
}
impl Drop for CodeDecodeGuard<'_> {
    fn drop(&mut self) { self.factory.store.borrow_mut().decoding_code.remove(&self.key); }
}

impl CallableReaderState {
    fn refresh(&self) {
        *self.dependencies.borrow_mut() = Datatype::resolved_dependencies(&self.datatype);
    }
}

impl std::ops::Deref for CallableReader {
    type Target = Datatype;
    fn deref(&self) -> &Datatype { &self.state.datatype }
}

impl CallableReader {
    pub fn datatype(&self) -> &Rc<Datatype> { &self.state.datatype }
    pub fn prototype(&self) -> Option<Rc<FuncProto>> {
        let root = Datatype::completed_record(&self.state.datatype);
        let code = root.get_ptr_to().unwrap_or(root);
        code.get_code_prototype().cloned()
    }
}

impl Datatype {
    pub fn is_host_type(&self) -> bool { self.host_type.get() }

    /// Finite reader-owned completion targets. No owning backedge is installed on a shell.
    pub fn resolved_dependencies(root: &Rc<Datatype>) -> Vec<Rc<Datatype>> {
        fn visit(ty: &Rc<Datatype>, seen: &mut std::collections::HashSet<*const Datatype>, result: &mut Vec<Rc<Datatype>>) {
            let ty = Datatype::completed_record(ty);
            if !seen.insert(Rc::as_ptr(&ty)) { return; }
            result.push(Rc::clone(&ty));
            if let Some(base) = &ty.typedef_imm { visit(base, seen, result); }
            if let Some(base) = &ty.qualified_base { visit(base, seen, result); }
            match &ty.kind {
                DatatypeKind::Pointer { ptrto, .. } => visit(ptrto, seen, result),
                DatatypeKind::PointerRel { ptrto, parent, .. } => { visit(ptrto, seen, result); visit(parent, seen, result); }
                DatatypeKind::Array { arrayof, .. } => visit(arrayof, seen, result),
                DatatypeKind::Struct { field, bitfield } => { for f in field { visit(&f.field_type, seen, result); } for f in bitfield { visit(&f.field_type, seen, result); } }
                DatatypeKind::Union { field } => for f in field { visit(&f.field_type, seen, result); },
                DatatypeKind::Code { proto: Some(p) } if p.has_store() => {
                    if let Some(t) = p.get_output_type() { visit(t, seen, result); }
                    for i in 0..p.num_params() { if let Some(t) = p.get_param(i).and_then(|p| p.get_type()) { visit(t, seen, result); } }
                }
                _ => {}
            }
        }
        let mut result = Vec::new();
        visit(root, &mut std::collections::HashSet::new(), &mut result);
        result
    }
}

impl TypeFactoryImpl {
    pub(super) fn begin_code_decode(&self, shell: &Rc<Datatype>) -> CodeDecodeGuard<'_> {
        let key = (shell.name.clone(), shell.id);
        self.store.borrow_mut().decoding_code.insert(key.clone());
        CodeDecodeGuard { factory: self, key }
    }
    /// Hold the same canonical callable root and only its missing resolved dependencies.
    pub fn hold_callable(&self, datatype: Rc<Datatype>) -> KunaResult<CallableReader> {
        let callable = datatype.get_metatype() == type_metatype::TYPE_CODE
            || datatype.get_ptr_to().is_some_and(|t| t.get_metatype() == type_metatype::TYPE_CODE);
        if !callable { return Err(KunaError::lowlevel("Semantic callable reader requires a callable type")); }
        let state = Rc::new(CallableReaderState { datatype, dependencies: RefCell::new(Vec::new()) });
        state.refresh();
        self.store.borrow_mut().callable_readers.push(Rc::downgrade(&state));
        Ok(CallableReader { state })
    }

    pub(super) fn refresh_callable_readers(&self) {
        let readers: Vec<_> = {
            let mut store = self.store.borrow_mut();
            store.callable_readers.retain(|reader| reader.strong_count() != 0);
            store.callable_readers.iter().filter_map(std::rc::Weak::upgrade).collect()
        };
        for reader in readers { reader.refresh(); }
    }

    /// Retain already-resolved dependencies on an independent source snapshot.
    pub fn retain_source_proto(&self, proto: Rc<FuncProto>) -> Rc<FuncProto> {
        proto.retain_resolved_dependencies();
        proto
    }
    pub(crate) fn reserve_nominal(&self, name: &str, id: u64, meta: type_metatype) -> KunaResult<Rc<Datatype>> {
        if id == 0 { return Err(KunaError::lowlevel("Nominal reservation requires producer identity")); }
        if let Some(existing) = self.find_by_id_local(name, id) {
            if existing.get_metatype() != meta { return Err(KunaError::lowlevel("Nominal identity changes metatype")); }
            return Ok(existing);
        }
        let mut shell = Datatype::new_with_align(if meta == type_metatype::TYPE_CODE { 1 } else { 0 }, 1, meta);
        shell.name = name.to_owned(); shell.display_name = name.to_owned(); shell.id = id;
        shell.flags |= flags::type_incomplete;
        shell.record_completion = Some(Rc::new(RefCell::new(std::rc::Weak::new())));
        shell.kind = match meta {
            type_metatype::TYPE_CODE => DatatypeKind::Code { proto: None },
            type_metatype::TYPE_UNION => { shell.flags |= flags::needs_resolution; DatatypeKind::Union { field: Vec::new() } },
            _ => DatatypeKind::Struct { field: Vec::new(), bitfield: Vec::new() },
        };
        let shell = Rc::new(shell);
        self.insert(Rc::clone(&shell))?;
        Ok(shell)
    }

    pub fn resolve_proto_model(&self, name: &str) -> KunaResult<Rc<crate::fspec::ProtoModel>> {
        if name.is_empty() || name == "default" { return self.defaultfp.borrow().clone().ok_or_else(|| KunaError::lowlevel("No default prototype model")); }
        self.proto_models.borrow().borrow().get(name).cloned().ok_or_else(|| KunaError::lowlevel(format!("Unknown prototype model: {name}")))
    }

    /// Supplied Ghidra prototypes may name a convention unknown to the compiler spec.
    /// Preserve its name and unknown status with the original default-model behavior.
    pub fn resolve_supplied_proto_model(&self, name: &str) -> KunaResult<Rc<crate::fspec::ProtoModel>> {
        if name.is_empty() || name == "default" { return self.resolve_proto_model(name); }
        if let Some(model) = self.proto_models.borrow().borrow().get(name) { return Ok(Rc::clone(model)); }
        let default = self.resolve_proto_model("default")?;
        let mut model = crate::fspec::ProtoModel::new_unknown(name, &default);
        if name == "unknown" { model.set_print_in_decl(false); }
        let model = Rc::new(model);
        self.proto_models.borrow().borrow_mut().insert(name.to_owned(), Rc::clone(&model));
        Ok(model)
    }

    /// Resolve by-value semantic facts before touching a physical call or entry.
    /// A pending declaration returns an error and remains available for a later retry.
    pub fn acquire_working_proto(&self, source: &FuncProto) -> KunaResult<FuncProto> {
        self.acquire_prototype(source, false)
    }

    /// Apply an entry declaration with the original bounded assignment diagnostic.
    /// Physical entries and declarations with explicit storage remain strict.
    pub(crate) fn apply_source_prototype(&self, source: &FuncProto) -> KunaResult<FuncProto> {
        self.acquire_prototype(source, true)
    }

    fn acquire_prototype(&self, source: &FuncProto, source_application: bool) -> KunaResult<FuncProto> {
        let mut working = FuncProto::new();
        working.copy(source);
        let logical = source.logical_pieces().filter(|pieces| {
            let output_supplied = pieces.outtype.as_ref().is_some_and(|t| t.get_metatype() == type_metatype::TYPE_VOID)
                || pieces.output_storage.as_ref().is_some_and(|p| !p.addr.is_invalid());
            let inputs_supplied = (0..pieces.intypes.len()).all(|i| pieces.input_storage.iter().any(|(slot, p)| *slot == i as int4 && !p.addr.is_invalid()));
            !(source.has_custom_storage() && output_supplied && inputs_supplied)
        });
        if let Some(logical) = logical {
            let mut pieces = logical.clone();
            pieces.outtype = logical.outtype.as_ref()
                .or_else(|| logical.output_storage.as_ref().and_then(|p| p.type_.as_ref()))
                .map(|t| self.ready_value_type(t)).transpose()?;
            if pieces.outtype.is_none() { pieces.outtype = Some(self.get_type_void()?); }
            pieces.intypes = logical.intypes.iter().map(|t| self.ready_value_type(t)).collect::<KunaResult<_>>()?;
            if pieces.intypes.iter().any(|t| matches!(t.get_metatype(), type_metatype::TYPE_VOID | type_metatype::TYPE_CODE)) {
                return Err(KunaError::lowlevel("Invalid by-value callable input type"));
            }
            // Finite logical overrides retain their independent variadic boundary.
            // Promote only the working tail before selecting physical storage.
            if source.is_override() && !source.is_dotdotdot() && !source.has_custom_storage()
                && pieces.input_storage.is_empty() && pieces.output_storage.is_none()
                && pieces.first_var_arg_slot >= 0
                && (pieces.first_var_arg_slot as usize) < pieces.intypes.len()
            {
                for ty in pieces.intypes.iter_mut().skip(pieces.first_var_arg_slot as usize) {
                    use type_metatype::*;
                    if matches!(ty.get_metatype(), TYPE_INT | TYPE_UINT | TYPE_ENUM_INT | TYPE_ENUM_UINT | TYPE_BOOL)
                        && ty.get_size() < self.get_size_of_int()
                    {
                        *ty = self.get_base(self.get_size_of_int(), TYPE_INT)?;
                    } else if ty.get_metatype() == TYPE_FLOAT
                        && ty.get_size() == self.get_size_of_float()
                        && ty.get_size() < self.get_size_of_double()
                    {
                        let ordinary = self.get_base(self.get_size_of_float(), TYPE_FLOAT)?;
                        let mut base = ty.as_ref();
                        while let Some(inner) = base.qualified_base().or_else(|| base.get_typedef()) {
                            base = inner;
                        }
                        if std::ptr::eq(base, ordinary.as_ref()) {
                            *ty = self.get_base(self.get_size_of_double(), TYPE_FLOAT)?;
                        }
                    }
                }
            }
            for (_, input) in &mut pieces.input_storage {
                input.type_ = input.type_.as_ref().map(|ty| self.ready_value_type(ty)).transpose()?;
            }
            let manager = self.manager.borrow().clone().ok_or_else(|| KunaError::lowlevel("No prototype address-space context"))?;
            let mut assigned = Vec::new();
            let source_refusal_allowed = source_application && !source.has_custom_storage()
                && pieces.input_storage.is_empty() && pieces.output_storage.is_none();
            let assignment = crate::kuna_customreturn::input_assignment(&pieces, self)?;
            match source.model().assign_parameter_storage(&assignment, &mut assigned, false, self, &manager) {
                Ok(()) => {}
                Err(KunaError::ParamUnassigned { .. }) if source_refusal_allowed => {
                    working.record_source_assignment_refusal();
                    working.retain_resolved_dependencies();
                    return Ok(working);
                }
                Err(error) => return Err(error),
            }
            if assigned.is_empty() { return Err(KunaError::lowlevel("Callable parameter storage unavailable")); }
            if let Some(output) = &pieces.output_storage { assigned[0] = output.clone(); }
            for (slot, input) in &pieces.input_storage {
                if *slot >= 0 {
                    if let Some(piece) = assigned.get_mut(*slot as usize + 1) { *piece = input.clone(); }
                }
            }
            let missing_output = assigned[0].type_.as_ref()
                .is_some_and(|t| t.get_metatype() != type_metatype::TYPE_VOID)
                && assigned[0].addr.is_invalid();
            let missing_input = assigned.iter().skip(1).any(|p| p.addr.is_invalid());
            if source_refusal_allowed && (missing_output || missing_input) {
                working.record_source_assignment_refusal();
                working.retain_resolved_dependencies();
                return Ok(working);
            }
            if missing_output {
                return Err(KunaError::lowlevel("Callable return storage unavailable"));
            }
            if missing_input { return Err(KunaError::lowlevel("Callable input storage unavailable")); }
            working.store_clear_all_inputs();
            assigned[0].flags |= source.get_output().get_flags();
            working.set_output(&assigned[0]);
            let mut name_index = 0usize;
            for (i, piece) in assigned.iter().enumerate().skip(1) {
                let hidden = piece.flags & crate::fspec::parameter_pieces_flags::HIDDENRETPARM != 0;
                let name = if hidden { "rethidden" } else { pieces.innames.get(name_index).map(String::as_str).unwrap_or("") };
                working.set_param((i - 1) as int4, name, piece);
                if !hidden { name_index += 1; }
            }
            // Allocation supplies roles; the declaration supplies independent locks/names.
            let mut source_slot = 0;
            for i in 0..working.num_params() {
                let p = working.get_param(i).expect("assigned parameter");
                let hidden = p.is_hidden_return();
                if hidden {
                    let original = source.get_param(i).filter(|parameter| parameter.is_hidden_return());
                    let piece = crate::fspec::ParameterPieces {
                        addr: p.get_address(), type_: p.get_type().cloned(),
                        flags: p.get_flags() | original.map(|parameter| parameter.get_flags()).unwrap_or_else(||
                            if source.is_output_locked() { crate::fspec::parameter_pieces_flags::TYPELOCK } else { 0 }),
                    };
                    working.set_param(i, original.map(|parameter| parameter.get_name()).unwrap_or("rethidden"), &piece);
                    if let Some(original) = original {
                        working.set_param_usepoint(i, original.get_usepoint());
                    }
                    continue;
                }
                if let Some(original) = (0..source.num_params()).filter_map(|i| source.get_param(i)).filter(|p| !p.is_hidden_return()).nth(source_slot) {
                    let mut piece = crate::fspec::ParameterPieces { addr: p.get_address(), type_: p.get_type().cloned(), flags: p.get_flags() | original.get_flags() };
                    piece.flags &= !(crate::fspec::parameter_pieces_flags::TYPELOCK | crate::fspec::parameter_pieces_flags::NAMELOCK);
                    piece.flags |= original.get_flags() & (crate::fspec::parameter_pieces_flags::TYPELOCK | crate::fspec::parameter_pieces_flags::NAMELOCK);
                    working.set_param(i, original.get_name(), &piece);
                    working.set_param_usepoint(i, original.get_usepoint());
                }
                source_slot += 1;
            }
            for (slot, input) in &pieces.input_storage {
                if *slot >= assigned.len() as int4 - 1 {
                    if input.addr.is_invalid() { return Err(KunaError::lowlevel("Callable input storage unavailable")); }
                    let original = source.get_param(*slot);
                    working.set_param(*slot, original.map(|p| p.get_name()).unwrap_or(""), input);
                    if let Some(original) = original {
                        working.set_param_usepoint(*slot, original.get_usepoint());
                    }
                }
            }
            working.update_this_pointer();
            working.set_output_lock(source.is_output_locked());
            working.set_model_lock(source.is_model_locked());
        } else if source.has_store() && !source.has_custom_storage()
            && (source.get_output_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID)
                && source.get_output().get_address().is_invalid()
                || (0..source.num_params()).any(|i| source.get_param(i)
                    .is_some_and(|parameter| parameter.get_address().is_invalid())))
        {
            working = self.complete_physical_entry_storage(source, working)?;
        } else if source.has_store() {
            if let Some(ty) = source.get_output_type() {
                let complete = self.ready_value_type(ty)?;
                if complete.get_metatype() != type_metatype::TYPE_VOID && source.get_output().get_address().is_invalid() {
                    return Err(KunaError::lowlevel("Supplied return storage unavailable"));
                }
                if !Rc::ptr_eq(&complete, ty) {
                    working.set_output(&crate::fspec::ParameterPieces {
                        addr: source.get_output().get_address(), type_: Some(complete), flags: source.get_output().get_flags(),
                    });
                }
            }
            for i in 0..source.num_params() {
                if let Some(param) = source.get_param(i) {
                    if param.get_address().is_invalid() {
                        return Err(KunaError::lowlevel("Supplied input storage unavailable"));
                    }
                    if let Some(ty) = param.get_type() {
                        let complete = self.ready_value_type(ty)?;
                        if !Rc::ptr_eq(&complete, ty) {
                            working.set_param(i, param.get_name(), &crate::fspec::ParameterPieces {
                                addr: param.get_address(), type_: Some(complete), flags: param.get_flags(),
                            });
                            working.set_param_usepoint(i, param.get_usepoint());
                        }
                    }
                }
            }
        }
        working.retain_resolved_dependencies();
        Ok(working)
    }

    // The physical-entry allocator retains supplied source slots except when
    // it inserts a previously absent hidden return carrier among ordinary inputs.
    fn physical_entry_input_slot(
        generated_hidden: bool,
        supplied_hidden: Option<int4>,
        assigned_index: int4,
        original_slot: Option<int4>,
    ) -> int4 {
        if generated_hidden && supplied_hidden.is_none() { assigned_index }
        else { original_slot.unwrap_or(assigned_index) }
    }

    /// Correspondence for an actual physical source and its acquired working copy.
    /// One item per compact source slot (including absent parameters). This is not
    /// a matcher for arbitrary or logical prototypes. No state is retained after
    /// the fresh receiver has imported its source symbols.
    pub(crate) fn physical_entry_parameter_slots<'a>(
        source: &'a FuncProto, working: &'a FuncProto,
    ) -> impl Iterator<Item = Option<int4>> + 'a {
        let eligible = source.logical_pieces().is_none() && !working.has_input_errors();
        let supplied_hidden = (0..source.num_params()).find(|&slot|
            source.get_param(slot).is_some_and(|parameter| parameter.is_hidden_return()));
        let generated_hidden = supplied_hidden.is_none() && (0..working.num_params()).any(|slot|
            working.get_param(slot).is_some_and(|parameter| parameter.is_hidden_return()));
        let mut ordinary = (0..working.num_params()).filter(|&slot| working.get_param(slot)
            .is_some_and(|parameter| !parameter.is_hidden_return()));
        (0..source.num_params()).map(move |source_slot| {
            if !eligible { return None; }
            source.get_param(source_slot)?;
            // Follow the allocator's original-parameter iteration. The model
            // may put `this` before the generated return pointer.
            let assigned_slot = if generated_hidden { ordinary.next()? } else { source_slot };
            let slot = Self::physical_entry_input_slot(generated_hidden, supplied_hidden,
                assigned_slot, Some(source_slot));
            working.get_param(slot).map(|_| slot)
        })
    }

    fn complete_physical_entry_storage(&self, source: &FuncProto, mut working: FuncProto) -> KunaResult<FuncProto> {
        use crate::fspec::{ParameterPieces, PrototypePieces, parameter_pieces_flags};
        if !source.has_model() {
            return Err(KunaError::lowlevel("Physical entry prototype model unavailable"));
        }
        let manager = self.manager.borrow().clone()
            .ok_or_else(|| KunaError::lowlevel("No prototype address-space context"))?;
        let mut pieces = PrototypePieces::default();
        pieces.first_var_arg_slot = source.get_first_var_arg_slot();
        pieces.outtype = source.get_output_type().map(|ty| self.ready_value_type(ty)).transpose()?;
        let mut supplied_hidden = None;
        let mut supplied_hidden_type = None;
        pieces.intypes = (0..source.num_params()).filter_map(|i| source.get_param(i).map(|parameter| (i, parameter)))
            .map(|(i, parameter)| {
                let ty = parameter.get_type().ok_or_else(|| KunaError::lowlevel("Physical entry input type unavailable"))
                    .and_then(|ty| self.ready_value_type(ty))?;
                if parameter.is_hidden_return() && supplied_hidden.is_none() {
                    supplied_hidden = Some(i);
                    supplied_hidden_type = Some(Rc::clone(&ty));
                }
                Ok(ty)
            }).collect::<KunaResult<_>>()?;
        let output_type = pieces.outtype.as_ref()
            .ok_or_else(|| KunaError::lowlevel("Physical entry output type unavailable"))?;
        let mut assigned = Vec::new();
        if !source.get_output().get_address().is_invalid() || output_type.get_metatype() == type_metatype::TYPE_VOID {
            assigned.push(ParameterPieces {
                addr: source.get_output().get_address(), type_: Some(Rc::clone(output_type)),
                flags: source.get_output().get_flags(),
            });
        } else {
            source.model().output().assign_map(&pieces, self, &mut assigned, &manager)?;
        }
        let generated_hidden = assigned.len() == 2;
        if generated_hidden && supplied_hidden.is_some() {
            let mut originals = (0..source.num_params()).filter(|&i| source.get_param(i).is_some());
            pieces.intypes.retain(|_| originals.next() != supplied_hidden);
        }
        source.model().assign_input_storage(&pieces, &mut assigned, self, &manager)?;
        if assigned[0].type_.as_ref().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID)
            && assigned[0].addr.is_invalid()
        {
            return Err(KunaError::lowlevel("Physical entry return storage unavailable"));
        }
        assigned[0].flags |= source.get_output().get_flags();
        working.store_clear_all_inputs();
        working.set_output(&assigned[0]);
        let mut originals = (0..source.num_params()).filter_map(|i| source.get_param(i).map(|parameter| (i, parameter)))
            .filter(|(i, _)| !generated_hidden || Some(*i) != supplied_hidden);
        for (index, assigned) in assigned.iter().skip(1).enumerate() {
            let hidden = generated_hidden && assigned.flags & parameter_pieces_flags::HIDDENRETPARM != 0;
            let original = if hidden {
                supplied_hidden.and_then(|i| source.get_param(i).map(|parameter| (i, parameter)))
            } else {
                originals.next()
            };
            let mut piece = assigned.clone();
            let slot = Self::physical_entry_input_slot(generated_hidden, supplied_hidden,
                index as int4, original.map(|(i, _)| i));
            let name = if let Some((_, parameter)) = original {
                if hidden {
                    piece.type_ = supplied_hidden_type.clone();
                }
                if !parameter.get_address().is_invalid() { piece.addr = parameter.get_address(); }
                piece.flags |= parameter.get_flags();
                parameter.get_name()
            } else {
                if source.is_output_locked() { piece.flags |= parameter_pieces_flags::TYPELOCK; }
                "rethidden"
            };
            if piece.addr.is_invalid() {
                return Err(KunaError::lowlevel("Physical entry input storage unavailable"));
            }
            working.set_param(slot, name, &piece);
            if let Some((_, parameter)) = original {
                working.set_param_usepoint(slot, parameter.get_usepoint());
            }
        }
        Ok(working)
    }

    pub(crate) fn ready_value_type(&self, ty: &Rc<Datatype>) -> KunaResult<Rc<Datatype>> {
        let resolved = Datatype::completed_record(ty);
        if resolved.is_incomplete() && !matches!(&resolved.kind, DatatypeKind::Pointer { .. } | DatatypeKind::PointerRel { .. }) { return Err(KunaError::lowlevel(format!("Pending callable datatype: {}", resolved.get_name()))); }
        if let DatatypeKind::Array { arrayof, arraysize } = &resolved.kind {
            let element = self.ready_value_type(arrayof)?;
            if !Rc::ptr_eq(&element, arrayof) { return self.get_type_array(*arraysize, element); }
        }
        if let DatatypeKind::Struct { field, bitfield } = &resolved.kind {
            let mut fields = None;
            for (index, f) in field.iter().enumerate() {
                let complete = self.ready_value_type(&f.field_type)?;
                if !Rc::ptr_eq(&complete, &f.field_type) {
                    fields.get_or_insert_with(|| field.clone())[index].field_type = complete;
                }
            }
            if let Some(fields) = fields {
                let mut complete = (*resolved).clone();
                complete.kind = DatatypeKind::Struct { field: fields, bitfield: bitfield.clone() };
                return Ok(Rc::new(complete));
            }
        } else if let DatatypeKind::Union { field } = &resolved.kind {
            let mut fields = None;
            for (index, f) in field.iter().enumerate() {
                let complete = self.ready_value_type(&f.field_type)?;
                if !Rc::ptr_eq(&complete, &f.field_type) {
                    fields.get_or_insert_with(|| field.clone())[index].field_type = complete;
                }
            }
            if let Some(fields) = fields {
                let mut complete = (*resolved).clone();
                complete.kind = DatatypeKind::Union { field: fields };
                return Ok(Rc::new(complete));
            }
        }
        Ok(resolved)
    }

    pub fn decode_proto(&self, decoder: &mut dyn Decoder, context: crate::fspec::PrototypeDecoding) -> KunaResult<FuncProto> {
        let mut proto = FuncProto::decode_wire(decoder, self, context)?;
        self.bind_prototype_injection(&mut proto)?;
        Ok(proto)
    }

    pub(crate) fn logical_types_ready(&self, pieces: &PrototypePieces) -> bool {
        fn ready(ty: &Rc<Datatype>) -> bool {
            let ty = Datatype::completed_record(ty);
            if matches!(&ty.kind, DatatypeKind::Pointer { .. } | DatatypeKind::PointerRel { .. }) { return true; }
            if ty.is_incomplete() { return false; }
            match &ty.kind {
                DatatypeKind::Array { arrayof, .. } => ready(arrayof),
                DatatypeKind::Struct { field, .. } | DatatypeKind::Union { field } => field.iter().all(|f| ready(&f.field_type)),
                _ => true,
            }
        }
        pieces.outtype.iter().chain(pieces.intypes.iter()).all(ready)
    }

    pub fn decode_type_with_code_flags(&self, decoder: &mut dyn Decoder, constructor: bool, destructor: bool) -> KunaResult<Rc<Datatype>> {
        let ty = self.decode_type(decoder)?;
        let mut value = (*ty).clone();
        if let DatatypeKind::Pointer { ptrto, spaceid, wordsize, truncate } = &ty.kind {
            let target = Datatype::completed_record(ptrto);
            let Some(proto) = target.get_code_prototype() else {
                return Err(KunaError::lowlevel("Special type decode does not see code"));
            };
            let mut p = FuncProto::new(); p.copy(proto);
            p.set_constructor(constructor); p.set_destructor(destructor);
            let mut code = (*target).clone();
            code.kind = DatatypeKind::Code { proto: Some(Rc::new(p)) };
            value.kind = DatatypeKind::Pointer {
                ptrto: Rc::new(code), spaceid: spaceid.clone(), wordsize: *wordsize, truncate: truncate.clone(),
            };
            return Ok(Rc::new(value));
        }
        Err(KunaError::lowlevel("Special type decode does not see pointer"))
    }
}
