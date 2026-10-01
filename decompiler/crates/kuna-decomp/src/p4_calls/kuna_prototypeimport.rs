//! Materialize host prototypes without declaration-style locking.
//!
//! The transport owns the temporary decode record; parameter-store semantics live
//! here. Function/localdb storage is committed; internal signatures can request
//! one ABI assignment pass. Neither path infers open recovery arity from the ABI boundary.

use std::rc::Rc;

use kuna_base::error::{KunaError, KunaResult};
use kuna_base::space::AddrSpaceManager;
use kuna_base::types::int4;

use crate::dtype::{type_metatype, TypeFactory, TypeFactoryImpl};
use crate::fspec::{
    callable_input_origins, physical_vararg_boundary, AbiInputOrigin, FirstVarArgCoordinate,
    LogicalCallable, parameter_pieces_flags, FuncProto, ParameterPieces, ProtoModel,
    PrototypePieces, EXTRAPOP_UNKNOWN,
};
use crate::remote_provider::RemoteProto;

impl RemoteProto {
    /// Preserve committed function/localdb storage. For an internal list with
    /// missing input or non-void output storage, assign the entire signature once
    /// through its model.
    pub(crate) fn to_func_proto(
        &self,
        model: Rc<ProtoModel>,
        types: &TypeFactoryImpl,
        manager: &AddrSpaceManager,
        coordinate: FirstVarArgCoordinate,
    ) -> KunaResult<FuncProto> {
        let mut proto = FuncProto::new();
        proto.set_internal(Rc::clone(&model), types.get_type_void()?);
        let out_type = self.out_type.as_ref().ok_or_else(|| {
            KunaError::lowlevel("Missing return type in host prototype")
        })?;
        let mut output = ParameterPieces {
            addr: self.out_storage.clone(),
            type_: Some(out_type.clone()),
            flags: self.out_flags,
        };
        let assign = self.internal_first.is_some()
            && ((out_type.get_metatype() != type_metatype::TYPE_VOID && self.out_storage.is_invalid())
                || self.params.iter().any(|p| p.storage.is_invalid()));
        let mut abi_first = self.internal_first.filter(|first| *first >= 0);
        let mut source = None;
        if assign {
            let declared: Vec<_> = self.params.iter().filter(|p| {
                p.flags & parameter_pieces_flags::HIDDENRETPARM == 0
            }).collect();
            let mut signature = PrototypePieces {
                outtype: Some(out_type.clone()),
                intypes: declared.iter().map(|p| p.dtype.clone().ok_or_else(|| {
                    KunaError::lowlevel("Missing type in host parameter")
                })).collect::<KunaResult<_>>()?,
                first_var_arg_slot: abi_first.map(|first| {
                    if coordinate == FirstVarArgCoordinate::Effective {
                        first
                    } else {
                        // Generic supplied-list indices refer to the decoded
                        // list, before explicitly tagged hidden inputs are removed.
                        self.params.iter().take(first as usize).filter(|p| {
                            p.flags & parameter_pieces_flags::HIDDENRETPARM == 0
                        }).count() as int4
                    }
                }).unwrap_or(-1),
                ..Default::default()
            };
            let mut assigned = Vec::new();
            model.assign_parameter_storage_for_supplied(
                &mut signature, &mut assigned, true, types, manager, coordinate,
            )?;
            let origins = callable_input_origins(&assigned, signature.intypes.len())?;
            abi_first = physical_vararg_boundary(&origins,
                (signature.first_var_arg_slot >= 0).then_some(signature.first_var_arg_slot));
            let Some(assigned_output) = assigned.first() else {
                return Err(KunaError::lowlevel("Prototype model did not assign a return parameter"));
            };
            output = assigned_output.clone();
            output.flags = self.out_flags | (output.flags & parameter_pieces_flags::INDIRECTSTORAGE);
            proto.set_output(&output);
            // A void physical result can be a successful indirect aggregate
            // result (for example Apple x8), or an ignored assignment failure.
            // Only the generated result role distinguishes those states.
            let result_assigned = assigned_output.type_.as_ref().is_some_and(|ty|
                (ty == out_type && (!output.addr.is_invalid()
                    || out_type.get_metatype() == type_metatype::TYPE_VOID))
                || (assigned_output.flags & parameter_pieces_flags::INDIRECTSTORAGE != 0
                    && origins.contains(&AbiInputOrigin::HiddenResult)));
            proto.set_output_lock(self.out_lock && result_assigned);
            if self.out_lock && result_assigned
                && out_type.get_metatype() != type_metatype::TYPE_UNKNOWN
                && declared.iter().all(|param|
                    param.flags & parameter_pieces_flags::TYPELOCK != 0
                        && param.dtype.as_ref().is_some_and(|ty|
                            ty.get_metatype() != type_metatype::TYPE_UNKNOWN))
            {
                // Assignment has already resolved the supplied boundary. Retain
                // the input declaration, not the ABI-transformed slot types.
                if signature.first_var_arg_slot >= 0 {
                    signature.first_var_arg_slot = signature.first_var_arg_slot.min(signature.intypes.len() as int4);
                }
                let logical = LogicalCallable::from_declaration(
                    types.model_binding_for(model.clone())?, &signature,
                    self.dotdotdot || signature.first_var_arg_slot >= 0,
                    !self.dotdotdot, 0,
                )?;
                source = Some((logical, origins));
            }
            let mut original = declared.iter();
            for (slot, piece) in assigned.iter_mut().enumerate().skip(1) {
                if piece.flags & parameter_pieces_flags::HIDDENRETPARM != 0 {
                    if proto.is_output_locked() {
                        piece.flags |= parameter_pieces_flags::TYPELOCK;
                    }
                    proto.set_param((slot - 1) as int4, "rethidden", piece);
                } else {
                    let param = original.next().ok_or_else(|| {
                        KunaError::lowlevel("Prototype model assigned unexpected input storage")
                    })?;
                    piece.flags = param.flags | (piece.flags
                        & (parameter_pieces_flags::ISTHIS | parameter_pieces_flags::INDIRECTSTORAGE));
                    if piece.flags & parameter_pieces_flags::TYPELOCK != 0
                        && piece.type_.as_ref().is_some_and(|t| t.get_metatype() == type_metatype::TYPE_UNKNOWN)
                    {
                        piece.flags |= parameter_pieces_flags::SIZELOCK;
                    }
                    proto.set_param((slot - 1) as int4, &param.name, piece);
                }
            }
            if original.next().is_some() {
                return Err(KunaError::lowlevel("Prototype model did not assign every input"));
            }
        } else {
            proto.set_output(&output);
            proto.set_output_lock(self.out_lock);
            for param in &self.params {
                let dtype = param.dtype.as_ref().ok_or_else(|| {
                    KunaError::lowlevel("Missing type in host parameter")
                })?;
                let slot = int4::try_from(param.index).map_err(|_| {
                    KunaError::lowlevel("Host parameter index exceeds prototype slot range")
                })?;
                let mut flags = param.flags;
                if (flags & parameter_pieces_flags::TYPELOCK) != 0
                    && dtype.get_metatype() == type_metatype::TYPE_UNKNOWN
                {
                    flags |= parameter_pieces_flags::SIZELOCK;
                }
                proto.set_param(slot, &param.name, &ParameterPieces {
                    addr: param.storage.clone(),
                    type_: Some(dtype.clone()),
                    flags,
                });
            }
        }
        if proto.get_output().get_type().is_some_and(|t| t.get_metatype() != type_metatype::TYPE_VOID)
            && proto.get_output().get_address().is_invalid()
        {
            return Err(KunaError::lowlevel("<returnsym> tag must include a valid storage address"));
        }
        proto.set_void_input_lock(self.voidlock);
        proto.set_abi_first_vararg(abi_first);
        proto.set_custom_storage(self.custom);
        proto.set_dotdotdot(self.dotdotdot);
        proto.set_no_return(self.no_return);
        proto.set_inline(self.inline);
        if self.constructor {
            proto.set_constructor(true);
        }
        proto.set_destructor(self.destructor);
        proto.merge_effect_overrides(&self.effects)?;
        proto.merge_likely_trash(&self.likely_trash);
        proto.set_model_lock(self.model_lock || proto.is_input_locked() || self.out_lock);
        if self.extrapop_seen {
            proto.set_extra_pop(self.extrapop.map(|v| v as int4).unwrap_or(EXTRAPOP_UNKNOWN));
        }
        if proto.get_extra_pop() == EXTRAPOP_UNKNOWN {
            proto.resolve_extra_pop();
        }
        proto.update_this_pointer();
        if let Some((logical, origins)) = source {
            proto.retain_logical_callable(types.get_type_code_proto(&logical)?, origins);
        } else if !assign {
            retain_tagged_source(&mut proto, types)?;
        }
        Ok(proto)
    }
}

/// Committed storage is never assigned again. Explicit indirect/hidden role
/// tags can nevertheless carry a complete semantic declaration through replay.
/// Untagged effective slots and incomplete/conflicting facts remain facts-only.
fn retain_tagged_source(proto: &mut FuncProto, types: &TypeFactoryImpl) -> KunaResult<()> {
    if !proto.is_output_locked() { return Ok(()); }
    let output = proto.get_output();
    let Some(output_type) = output.get_type() else { return Ok(()) };
    if output_type.get_metatype() == type_metatype::TYPE_UNKNOWN { return Ok(()); }
    if !output.is_indirect_storage() && !(0..proto.num_params()).any(|slot|
        proto.get_param(slot).is_some_and(|param|
            param.is_hidden_return() || param.is_indirect_storage()))
    {
        return Ok(());
    }
    let mut hidden_result = None;
    let mut inputs = Vec::with_capacity(proto.num_params() as usize);
    let mut origins = Vec::with_capacity(proto.num_params() as usize);
    for slot in 0..proto.num_params() {
        let Some(param) = proto.get_param(slot) else { return Ok(()) };
        let Some(ty) = param.get_type() else { return Ok(()) };
        if !param.is_type_locked() || ty.get_metatype() == type_metatype::TYPE_UNKNOWN {
            return Ok(());
        }
        if param.is_hidden_return() {
            if hidden_result.is_some() || param.is_indirect_storage() { return Ok(()); }
            let Some(result) = ty.get_ptr_to() else { return Ok(()) };
            hidden_result = Some(result);
            origins.push(AbiInputOrigin::HiddenResult);
        } else {
            let logical_type = if param.is_indirect_storage() {
                let Some(pointee) = ty.get_ptr_to() else { return Ok(()) };
                pointee
            } else {
                ty.clone()
            };
            if logical_type.get_metatype() == type_metatype::TYPE_UNKNOWN { return Ok(()); }
            origins.push(AbiInputOrigin::Declared(inputs.len()));
            inputs.push(logical_type);
        }
    }
    let result = if output.is_indirect_storage() {
        let Some(result) = hidden_result else { return Ok(()) };
        if output_type.get_metatype() != type_metatype::TYPE_VOID
            && output_type.get_ptr_to().as_ref() != Some(&result)
        {
            return Ok(());
        }
        result
    } else {
        if hidden_result.is_some() { return Ok(()); }
        output_type.clone()
    };
    if result.get_metatype() == type_metatype::TYPE_UNKNOWN { return Ok(()); }
    let first = proto.get_abi_first_vararg().map(|first|
        origins.iter().take(first as usize).filter(|role|
            matches!(role, AbiInputOrigin::Declared(_))).count() as int4);
    let pieces = PrototypePieces {
        outtype: Some(result),
        intypes: inputs,
        first_var_arg_slot: first.unwrap_or(-1),
        ..Default::default()
    };
    let logical = LogicalCallable::from_declaration(
        types.model_binding_for(proto.model().clone())?, &pieces,
        proto.is_dotdotdot() || first.is_some(), !proto.is_dotdotdot(), 0,
    )?;
    proto.retain_logical_callable(types.get_type_code_proto(&logical)?, origins);
    Ok(())
}
