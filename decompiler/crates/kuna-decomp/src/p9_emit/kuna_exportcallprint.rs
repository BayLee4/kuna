//! Typed physical/source callable identities, before PrintC flattens tokens.
use super::*;
use crate::kuna_exportcall::{ExportBinding, ExportCall, ExportInputSpec};
use crate::fspec::FuncProto;

/// Resolve one prepared carrier to the same finalized actual occurrence used
/// by typed call printing. The working formal already owns its decoded storage.
fn export_argument_value(fd:&Funcdata,index:i32,call:&ExportCall,slot:usize) -> Option<crate::context::VarnodeId> {
    let actual = fd.get_call_specs(index);
    let operation = fd.obank().get(actual.get_op())?;
    let required = call.working.get_param(slot as i32)?;
    let storage = actual.final_input_storage();
    let aligned = storage.len() + 1 == operation.num_input() as usize;
    (1..operation.num_input()).find_map(|slot| {
        let home = if aligned { storage.get((slot-1) as usize).cloned() }
            else { actual.proto().get_param(slot-1).map(|p| (p.get_address(),p.get_size())) };
        home.filter(|(at,size)| at.justified_contain(*size,&required.get_address(),required.get_size(),false) == 0)
            .and_then(|_| operation.get_in(slot))
    })
}

/// Recheck the expression type at the final publication boundary: a later
/// physical-parameter edit can change a caller's declaration after preparation.
/// Missing occurrences retain the existing explicit printing error path.
fn direct_delivery_printable(fd:&Funcdata,index:i32,call:&ExportCall) -> bool {
    call.spec.direct.is_none() || call.spec.inputs.iter().enumerate().all(|(slot,required)| {
        let Some(value) = export_argument_value(fd,index,call,slot) else { return true; };
        let Some(node) = fd.vbank().get(value) else { return true; };
        let emitted_type = declared_variable_type(fd,fd.get_arch().decl_high_type,value)
            .unwrap_or_else(|| std::rc::Rc::clone(node.get_type()));
        emitted_type.get_size() <= required.size
            || required.unsigned && matches!(emitted_type.get_metatype(),
                type_metatype::TYPE_INT|type_metatype::TYPE_UINT)
    })
}

impl PrintC {
    /// Types named by the invocation's additional signatures and conversions.
    /// A private physical Funcdata does not contain its source wrapper's types.
    pub(super) fn export_type_roots<'a>(
        &'a self, fd: &'a Funcdata,
    ) -> impl Iterator<Item = &'a std::rc::Rc<crate::dtype::Datatype>> {
        fn signature_types(proto: &FuncProto) -> impl Iterator<Item = &std::rc::Rc<crate::dtype::Datatype>> {
            proto.get_output_type().into_iter().chain(
                (0..proto.num_params()).filter_map(|slot| proto.get_param(slot).and_then(|p| p.get_type()))
            )
        }
        self.export_binding.as_ref()
            .filter(|_| self.out_lang == crate::kuna_lang::OutLang::C)
            .into_iter().flat_map(move |binding| {
                let own = binding.function(fd.get_address()).into_iter().flat_map(|function| {
                    std::iter::once(&function.working)
                        .chain(function.spec.wrapper.then_some(function.source.as_ref()))
                });
                let calls = binding.calls_for(fd.get_address()).flat_map(move |call| {
                    binding.requires_helper(call).then_some(&call.working).into_iter()
                        .chain(call.spec.direct.is_none().then_some(call.source_geometry.as_ref()))
                        .chain(call.spec.targets.iter().filter_map(|address| binding.function_at(address))
                            .flat_map(move |target| std::iter::once(&target.working)
                                .chain((call.spec.direct.is_none() && target.spec.wrapper)
                                    .then_some(target.source.as_ref()))))
                        .flat_map(signature_types)
                        .chain(call.pointer.iter().filter(move |_| call.spec.direct.is_none()))
                });
                // Authored direct sites need a selected implementation declaration
                // even when no inferred physical binding owns the occurrence.
                let direct = (0..fd.num_calls()).filter_map(move |index| {
                    let call = fd.get_call_specs(index);
                    let op = call.get_op();
                    if !fd.obank().get(op).is_some_and(|op| op.code() == OpCode::CPUI_CALL) { return None; }
                    let target = binding.function(call.get_entry_address())?;
                    if !target.spec.private { return None; }
                    let same_name = if call.get_name().is_empty() {
                        self.call_callee_name(fd,op) == target.spec.implementation
                    } else { call.get_name() == target.spec.implementation };
                    same_name.then_some(&target.working)
                });
                own.flat_map(signature_types).chain(calls).chain(direct.flat_map(signature_types))
            })
    }

    pub(super) fn begin_export_publication(&mut self,fd:&Funcdata) {
        self.export_proto_count = 0;
        self.export_calls.clear();
        if let Some(binding) = &self.export_binding {
            self.export_calls.extend(binding.bound_calls(fd).into_iter()
                .filter(|(index,call)| direct_delivery_printable(fd,*index,call))
                .map(|(index,call)| (fd.get_call_specs(index).get_op(),call)));
        }
        self.export_publication = self.export_binding.as_ref()
            .filter(|_| self.out_lang == crate::kuna_lang::OutLang::C)
            .and_then(|binding| {
                let function = binding.function(fd.get_address());
                if !binding.contains(fd.get_address()) { return None; }
                let name = function.map_or_else(|| fd.get_display_name().to_owned(),|function| function.spec.name.clone());
                let implementation = function.map_or_else(|| name.clone(),|function| function.spec.implementation.clone());
                Some(crate::kuna_exportcall::ExportPublication {
                    entry: fd.get_address().clone(), source_name:name, implementation,
                    private:function.is_some_and(|function| function.spec.private),
                    public_prototype:-1,declarations:Vec::new(),
                })
            });
    }

    pub(super) fn record_export_declaration(&mut self,name:&str,role:&'static str) {
        if let Some(publication) = &mut self.export_publication {
            let index = self.export_proto_count;
            if role == "public" && name == publication.source_name {
                publication.public_prototype = index as i32;
            }
            publication.declarations.push(crate::kuna_exportcall::ExportDeclaration {
                index,name:name.to_owned(),role,
            });
        }
    }

    fn export_declarator(&mut self, ty: &std::rc::Rc<crate::dtype::Datatype>, name: &str) {
        let spelling = typed_declarator_parts(ty, &self.rt_ctx);
        let markup = MarkupRef::none();
        self.emit_typed_declarator_part(&spelling.front, &spelling.front_types, &markup);
        if !spelling.front.ends_with('*') { self.emit.spaces(1,0); }
        self.emit.tag_variable(name,SyntaxHighlight::VarColor,&markup);
        self.emit_typed_declarator_part(&spelling.back,&spelling.back_types,&markup);
    }

    pub(super) fn emit_export_signature(&mut self, proto: &FuncProto, name: &str, private: bool, arch:&Architecture) -> KunaResult<()> {
        let markup = MarkupRef::none();
        self.export_proto_count += 1;
        let id = self.emit.begin_func_proto();
        if private { self.emit.print("static ",SyntaxHighlight::KeywordColor); }
        let output = proto.get_output_type().ok_or_else(|| KunaError::lowlevel("Untyped physical export return"))?;
        let spelling = typed_type_name_for_decl(output,&self.rt_ctx);
        let ret = self.emit.begin_return_type(&markup);
        self.emit_typed_declarator_part(&spelling.front,&spelling.front_types,&markup);
        self.emit.end_return_type(ret);
        self.emit.spaces(1,0);
        if self.options.convention && arch.model_print_in_decl(proto) {
            self.emit.print(proto.get_model_name(),if proto.is_model_unknown() { SyntaxHighlight::ErrorColor } else { SyntaxHighlight::KeywordColor });
            self.emit.spaces(1,0);
        }
        self.emit.tag_func_name(name,SyntaxHighlight::FuncnameColor,&markup);
        let paren = self.emit.open_paren("(",0);
        if proto.num_params() == 0 { self.emit.print("void",SyntaxHighlight::KeywordColor); }
        for slot in 0..proto.num_params() {
            if slot > 0 { self.emit.print(",",SyntaxHighlight::NoColor); }
            let parameter = proto.get_param(slot).expect("export parameter");
            let ty = parameter.get_type().ok_or_else(|| KunaError::lowlevel("Untyped physical export input"))?;
            let default;
            let name = if parameter.get_name().is_empty() { default = format!("param_{}",slot+1); &default } else { parameter.get_name() };
            self.export_declarator(ty,name);
        }
        if proto.is_dotdotdot() {
            if proto.num_params() > 0 { self.emit.print(",",SyntaxHighlight::NoColor); }
            self.emit.print("...",SyntaxHighlight::NoColor);
        }
        self.emit.close_paren(")",paren);
        self.emit_typed_declarator_part(&spelling.back,&spelling.back_types,&markup);
        self.emit.end_func_proto(id);
        Ok(())
    }

    pub(super) fn emit_export_declarations(&mut self, fd:&Funcdata, arch:&Architecture) -> KunaResult<()> {
        if self.out_lang != crate::kuna_lang::OutLang::C { return Ok(()); }
        let Some(binding) = self.export_binding.clone() else { return Ok(()); };
        let calls = binding.calls_for(fd.get_address()).collect::<Vec<_>>();
        if !calls.is_empty() || binding.function(fd.get_address()).is_some() {
            let function = binding.function(fd.get_address());
            let name = function.map_or_else(|| fd.get_display_name().to_owned(), |function| function.spec.implementation.clone());
            self.record_export_declaration(&name,if function.is_some_and(|function| function.spec.private) { "implementation" } else { "public" });
            self.emit.tag_line();
            if let Some(function) = function {
                self.emit_export_signature(&function.working,&name,function.spec.private,arch)?;
            } else {
                self.emit_prototype_declaration(fd,arch,&MarkupRef::none())?;
            }
            self.emit.print(";",SyntaxHighlight::NoColor);
        }
        let mut emitted = std::collections::BTreeSet::new();
        for call in &calls {
            for address in &call.spec.targets {
                let Some(target) = binding.function_at(address) else { continue };
                if emitted.insert(target.spec.implementation.clone()) {
                    self.emit.tag_line();
                    self.record_export_declaration(&target.spec.implementation,"dependency");
                    self.emit_export_signature(&target.working,&target.spec.implementation,target.spec.private,arch)?;
                    self.emit.print(";",SyntaxHighlight::NoColor);
                }
                if call.spec.direct.is_none() && target.spec.wrapper && emitted.insert(target.spec.name.clone()) {
                    self.emit.tag_line();
                    self.record_export_declaration(&target.spec.name,"dependency");
                    self.emit_export_signature(&target.source,&target.spec.name,false,arch)?;
                    self.emit.print(";",SyntaxHighlight::NoColor);
                }
            }
        }
        // An authored site keeps its own prototype and is deliberately not
        // reseeded from an inferred binding. It still references the selected
        // private definition, whose real signature must precede this body.
        // Declaration closure does not certify that the site is compatible.
        for index in 0..fd.num_calls() {
            let call = fd.get_call_specs(index);
            let op = call.get_op();
            if !fd.obank().get(op).is_some_and(|op| op.code() == OpCode::CPUI_CALL) { continue; }
            let Some(target) = binding.function(call.get_entry_address()) else { continue };
            if !target.spec.private || emitted.contains(&target.spec.implementation) { continue; }
            let same_name = if call.get_name().is_empty() {
                self.call_callee_name(fd,op) == target.spec.implementation
            } else {
                call.get_name() == target.spec.implementation
            };
            if !same_name { continue; }
            emitted.insert(target.spec.implementation.clone());
            self.emit.tag_line();
            self.record_export_declaration(&target.spec.implementation,"dependency");
            self.emit_export_signature(&target.working,&target.spec.implementation,true,arch)?;
            self.emit.print(";",SyntaxHighlight::NoColor);
        }
        // Only a genuine pointer/code value can escape a callable identity;
        // an unrelated integer with an equal offset is not such evidence.
        for operation in fd.obank().iter_alive().filter_map(|id| fd.obank().get(id)) {
            for id in (0..operation.num_input()).filter_map(|slot| operation.get_in(slot)).chain(operation.get_out()) {
                let Some(value) = fd.vbank().get(id) else { continue };
                if !value.get_type().get_ptr_to().is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_CODE) { continue; }
                let Some(offset) = crate::kuna_callbacktype::code_address(fd,id,0) else { continue; };
                if value.get_def().and_then(|id| fd.obank().get(id))
                    .filter(|op| op.code() == OpCode::CPUI_PTRSUB)
                    .and_then(|op| op.get_in(0)).and_then(|id| fd.vbank().get(id))
                    .and_then(|base| base.get_type().get_ptr_to())
                    .and_then(|base| base.spacebase_parts())
                    .is_some_and(|(_,frame)| !frame.is_invalid())
                {
                    continue;
                }
                let Some(space) = value.get_type().get_pointer_space().or_else(|| arch.manage().get_default_code_space().cloned()) else { continue; };
                let mut encoding = 0;
                let address = arch.resolve_constant(&space,offset,value.get_size(),operation.get_addr(),&mut encoding)?;
                if binding.function(&address).is_some_and(|target| target.spec.private && !target.spec.wrapper) {
                    return Err(KunaError::lowlevel("Selected physical callable has no constructible source-compatible escaping identity"));
                }
            }
        }
        for call in calls {
            if binding.requires_helper(call) { self.emit_export_helper(&binding,call)?; }
        }
        Ok(())
    }

    fn emit_export_helper(&mut self,binding:&ExportBinding,call:&ExportCall) -> KunaResult<()> {
        self.emit.tag_line();
        self.record_export_declaration(&call.helper,"helper");
        self.export_proto_count += 1;
        let prototype = self.emit.begin_func_proto();
        let markup = MarkupRef::none();
        let output = call.working.get_output_type().ok_or_else(|| KunaError::lowlevel("Untyped export helper return"))?;
        let spelling = typed_type_name_for_decl(output,&self.rt_ctx);
        self.emit.print("static ",SyntaxHighlight::KeywordColor);
        self.emit_typed_declarator_part(&spelling.front,&spelling.front_types,&markup);
        self.emit.spaces(1,0);
        self.emit.tag_func_name(&call.helper,SyntaxHighlight::FuncnameColor,&markup);
        let paren = self.emit.open_paren("(",0);
        if call.spec.direct.is_none() {
            self.export_declarator(call.pointer.as_ref().ok_or_else(|| KunaError::lowlevel("Export helper lacks source-compatible pointer"))?,"kuna_callback");
        } else if call.working.num_params() == 0 {
            self.emit.print("void",SyntaxHighlight::KeywordColor);
        }
        for slot in 0..call.working.num_params() {
            if slot > 0 || call.spec.direct.is_none() { self.emit.print(",",SyntaxHighlight::NoColor); }
            let parameter = call.working.get_param(slot).expect("helper input");
            self.export_declarator(parameter.get_type().expect("typed helper input"),&format!("kuna_value{slot}"));
        }
        self.emit.close_paren(")",paren);
        self.emit_typed_declarator_part(&spelling.back,&spelling.back_types,&markup);
        self.emit.end_func_proto(prototype);
        let body = self.emit.open_brace_indent("{",EmitBraceStyle::SameLine);
        if let Some(address) = &call.spec.direct {
            let target = binding.function_at(address).ok_or_else(|| KunaError::lowlevel("Unknown selected direct implementation"))?;
            self.emit.tag_line();
            self.export_call_statement(&target.working,&target.spec.implementation,&target.spec.inputs,&call.spec.inputs,&call.working,false,true)?;
            self.emit.close_brace_indent("}",body);
            self.emit.tag_line();
            return Ok(());
        }
        for target in &call.spec.targets {
            let target = binding.function_at(target).ok_or_else(|| KunaError::lowlevel("Unknown selected indirect implementation"))?;
            if target.spec.private && !target.spec.wrapper {
                return Err(KunaError::lowlevel("Selected indirect target has no constructible source identity"));
            }
            self.emit.tag_line();
            self.emit.print("if (kuna_callback == ",SyntaxHighlight::NoColor);
            self.emit.tag_func_name(&target.spec.name,SyntaxHighlight::FuncnameColor,&markup);
            self.emit.print(")",SyntaxHighlight::NoColor);
            let branch = self.emit.open_brace_indent("{",EmitBraceStyle::SameLine);
            self.emit.tag_line();
            self.export_call_statement(&target.working,&target.spec.implementation,&target.spec.inputs,&call.spec.inputs,&call.working,false,false)?;
            if output.get_metatype() == type_metatype::TYPE_VOID { self.emit.tag_line(); self.emit.print("return;",SyntaxHighlight::KeywordColor); }
            self.emit.close_brace_indent("}",branch);
        }
        // Unknown/native targets retain exactly their ordinary source call.
        // This is not a claim that the source pointer carries raw upper bits.
        self.emit.tag_line();
        let source_inputs = source_inputs(&call.source_geometry);
        self.export_call_statement(&call.source_geometry,"kuna_callback",&source_inputs,&call.spec.inputs,&call.working,true,false)?;
        self.emit.close_brace_indent("}",body);
        self.emit.tag_line();
        Ok(())
    }

    fn export_call_statement(&mut self,proto:&FuncProto,name:&str,inputs:&[ExportInputSpec],available:&[ExportInputSpec],available_proto:&FuncProto,source_call:bool,exact_storage:bool) -> KunaResult<()> {
        let markup = MarkupRef::none();
        if proto.get_output_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID) {
            self.emit.print("return ",SyntaxHighlight::KeywordColor);
        }
        self.emit.tag_func_name(name,SyntaxHighlight::FuncnameColor,&markup);
        let paren = self.emit.open_paren("(",0);
        for (slot,input) in inputs.iter().enumerate() {
            if slot > 0 { self.emit.print(",",SyntaxHighlight::NoColor); }
            let index = available.iter().position(|candidate| if exact_storage {
                candidate.storage == input.storage && candidate.size == input.size
            } else { candidate.storage.space == input.storage.space
                && candidate.storage.offset <= input.storage.offset
                && input.storage.offset.saturating_add(input.size as u64) <= candidate.storage.offset.saturating_add(candidate.size as u64) })
                .ok_or_else(|| KunaError::lowlevel("Source-compatible callback argument is not constructible from the physical occurrence"))?;
            let parameter = proto.get_param(slot as i32).ok_or_else(|| KunaError::lowlevel("Export parameter occurrence mismatch"))?;
            let ty = parameter.get_type().ok_or_else(|| KunaError::lowlevel("Untyped export parameter"))?;
            let raw = available_proto.get_param(index as i32).and_then(|p| p.get_type())
                .ok_or_else(|| KunaError::lowlevel("Untyped export carrier"))?;
            // An unknown target is an ordinary source call, not a private
            // machine-carrier boundary. In particular, source _Bool requires
            // value normalization, never an arbitrary byte representation.
            let transfer = if source_call && ty.get_metatype() == type_metatype::TYPE_BOOL {
                let spelling = typed_declarator_parts(ty,&self.rt_ctx);
                self.emit.print("(",SyntaxHighlight::NoColor);
                self.emit_typed_declarator_part(&spelling.front,&spelling.front_types,&markup);
                self.emit_typed_declarator_part(&spelling.back,&spelling.back_types,&markup);
                self.emit.print(")",SyntaxHighlight::NoColor);
                false
            } else {
                self.export_conversion_open(raw,ty)
            };
            self.emit.tag_variable(&format!("kuna_value{index}"),SyntaxHighlight::VarColor,&markup);
            self.export_conversion_close(transfer);
        }
        self.emit.close_paren(")",paren);
        self.emit.print(";",SyntaxHighlight::NoColor);
        Ok(())
    }

    // A carrier is storage, not a numeric value in the edited parameter's
    // domain. Use the same compound-literal union transfer as op_bit_transfer_ir.
    fn export_conversion_open(&mut self,from:&std::rc::Rc<crate::dtype::Datatype>,to:&std::rc::Rc<crate::dtype::Datatype>) -> bool {
        if std::rc::Rc::ptr_eq(from,to) { return false; }
        if from.get_size() == to.get_size() {
            self.emit.print("((union { ",SyntaxHighlight::NoColor);
            self.export_declarator(from,"from");
            self.emit.print("; ",SyntaxHighlight::NoColor);
            self.export_declarator(to,"to");
            self.emit.print("; }){ .from = ",SyntaxHighlight::NoColor);
            true
        } else {
            let spelling = typed_declarator_parts(to,&self.rt_ctx);
            self.emit.print("(",SyntaxHighlight::NoColor);
            self.emit_typed_declarator_part(&spelling.front,&spelling.front_types,&MarkupRef::none());
            self.emit_typed_declarator_part(&spelling.back,&spelling.back_types,&MarkupRef::none());
            self.emit.print(")",SyntaxHighlight::NoColor);
            false
        }
    }

    fn export_conversion_close(&mut self,transfer:bool) {
        if transfer { self.emit.print(" }).to",SyntaxHighlight::NoColor); }
    }

    fn push_export_conversion_open_ir(&mut self,from:&std::rc::Rc<crate::dtype::Datatype>,to:&std::rc::Rc<crate::dtype::Datatype>,op:OpId) -> bool {
        if std::rc::Rc::ptr_eq(from,to) { return false; }
        if from.get_size() != to.get_size() {
            self.push_cast_open(to,op);
            return true;
        }
        static BITS: OpToken = op_token("", " }).to", 2, 66, false, TokenType::Postsurround, 0, 0);
        self.push_op(&BITS,Some(op_key(op)));
        for _ in 0..4 { self.push_op(&TYPED_DECL_JOIN,Some(op_key(op))); }
        self.push_atom(&Atom::syntax("((union { ",TagType::Syntax,crate::printlanguage::SyntaxHighlight::no_color));
        self.push_typed_declarator_ir(from,"from",op);
        self.push_atom(&Atom::syntax("; ",TagType::Syntax,crate::printlanguage::SyntaxHighlight::no_color));
        self.push_typed_declarator_ir(to,"to",op);
        self.push_atom(&Atom::syntax("; }){ .from = ",TagType::Syntax,crate::printlanguage::SyntaxHighlight::no_color));
        false
    }

    pub(super) fn emit_export_wrapper(&mut self,fd:&Funcdata,arch:&Architecture) -> KunaResult<()> {
        if self.out_lang != crate::kuna_lang::OutLang::C { return Ok(()); }
        let Some(function) = self.export_binding.as_ref().and_then(|binding| binding.function(fd.get_address())).cloned() else { return Ok(()); };
        if !function.spec.wrapper { return Ok(()); }
        self.emit.tag_line();
        self.record_export_declaration(&function.spec.name,"public");
        self.emit_export_signature(&function.source,&function.spec.name,false,arch)?;
        let body = self.emit.open_brace_indent("{",EmitBraceStyle::SameLine);
        self.emit.tag_line();
        if function.source.get_output_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID) { self.emit.print("return ",SyntaxHighlight::KeywordColor); }
        self.emit.tag_func_name(&function.spec.implementation,SyntaxHighlight::FuncnameColor,&MarkupRef::none());
        let paren = self.emit.open_paren("(",0);
        for (slot,input) in function.spec.inputs.iter().enumerate() {
            if slot > 0 { self.emit.print(",",SyntaxHighlight::NoColor); }
            let source = function.source.get_param(input.source_slot).ok_or_else(|| KunaError::lowlevel("Unconstructible source export wrapper"))?;
            let default;
            let name = if source.get_name().is_empty() { default = format!("param_{}",input.source_slot+1); &default } else { source.get_name() };
            let raw = if input.unsigned { arch.types().get_base(input.size,type_metatype::TYPE_UINT)? }
                else { source.get_type().cloned().ok_or_else(|| KunaError::lowlevel("Untyped source wrapper input"))? };
            let ty = function.working.get_param(slot as i32).and_then(|p| p.get_type())
                .ok_or_else(|| KunaError::lowlevel("Untyped physical wrapper input"))?;
            let transfer = self.export_conversion_open(&raw,ty);
            if input.unsigned {
                let spelling = typed_declarator_parts(&raw,&self.rt_ctx);
                self.emit.print("(",SyntaxHighlight::NoColor);
                self.emit_typed_declarator_part(&spelling.front,&spelling.front_types,&MarkupRef::none());
                self.emit_typed_declarator_part(&spelling.back,&spelling.back_types,&MarkupRef::none());
                self.emit.print(")",SyntaxHighlight::NoColor);
            }
            self.emit.tag_variable(name,SyntaxHighlight::VarColor,&MarkupRef::none());
            self.export_conversion_close(transfer);
        }
        self.emit.close_paren(")",paren);
        self.emit.print(";",SyntaxHighlight::NoColor);
        self.emit.close_brace_indent("}",body);
        self.emit.tag_line();
        Ok(())
    }

    pub(super) fn op_export_call_ir(&mut self,fd:&Funcdata,arch:&Architecture,op:OpId,call:&ExportCall) -> KunaResult<()> {
        let index = fd.get_call_specs_index(op).ok_or_else(|| KunaError::lowlevel("Missing export call occurrence"))?;
        let operation = fd.obank().get(op).expect("export call operation");
        let values = call.spec.inputs.iter().enumerate().map(|(slot,_)| {
            export_argument_value(fd,index,call,slot)
                .ok_or_else(|| KunaError::lowlevel("Selected physical call input has no actual storage occurrence"))
        }).collect::<KunaResult<Vec<_>>>()?;
        self.push_op(&tokens::FUNCTION_CALL,Some(op_key(op)));
        let binding = self.export_binding.clone();
        let helper = binding.as_ref().is_some_and(|binding| binding.requires_helper(call));
        let target = call.spec.direct.as_ref().map(|target| {
            binding.as_ref().and_then(|binding| binding.function_at(target))
                .ok_or_else(|| KunaError::lowlevel("Selected physical implementation is unavailable"))
        }).transpose()?;
        let name = if helper { call.helper.clone() }
            else { target.as_ref().expect("direct implementation").spec.implementation.clone() };
        self.push_atom(&Atom::with_op(name,TagType::FuncToken,crate::printlanguage::SyntaxHighlight::funcname_color,op_key(op)));
        let count = values.len() + usize::from(call.spec.direct.is_none());
        for _ in 1..count { self.push_op(&tokens::COMMA,Some(op_key(op))); }
        if call.spec.direct.is_none() {
            let callee = operation.get_in(0).ok_or_else(|| KunaError::lowlevel("Missing source-compatible indirect callee"))?;
            self.push_vn_ir(fd,arch,callee,op)?;
        }
        for (index,value) in values.into_iter().enumerate() {
            let raw = call.working.get_param(index as i32).and_then(|p| p.get_type())
                .ok_or_else(|| KunaError::lowlevel("Untyped selected physical carrier"))?;
            let actual_type = declared_variable_type(fd,arch.decl_high_type,value)
                .unwrap_or_else(|| std::rc::Rc::clone(fd.vbank().get(value).expect("physical argument").get_type()));
            let close_raw = self.push_export_conversion_open_ir(&actual_type,raw,op);
            self.push_vn_ir(fd,arch,value,op)?;
            if close_raw { self.push_cast_close(raw); }
        }
        if count == 0 {
            self.push_atom(&Atom::syntax("",TagType::BlankToken,crate::printlanguage::SyntaxHighlight::no_color));
        }
        Ok(())
    }
}
fn source_inputs(source:&FuncProto) -> Vec<ExportInputSpec> {
    (0..source.num_params()).filter_map(|slot| source.get_param(slot).map(|parameter| ExportInputSpec {
        storage: crate::kuna_exportcall::ExportAddress::new(&parameter.get_address()),size:parameter.get_size(),source_slot:slot,unsigned:false,name:parameter.get_name().to_owned(),
    })).collect()
}
