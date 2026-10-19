//! Declared pointer contracts at address uses, including escaped frame views.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_base::space::AddrSpace;
use kuna_num::opcodes::OpCode;

use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, Datatype, TypeFactory};
use crate::funcdata::Funcdata;
use crate::userop::BUILTIN_VOLATILE_WRITE;

fn storage_type(fd: &Funcdata, address: &Address, width: i32) -> KunaResult<Option<Rc<Datatype>>> {
    let Some(entry) = fd
        .get_arch()
        .query_container_global(address, width, &Address::new_invalid())? else { return Ok(None) };
    if !entry.is_type_locked() {
        return Ok(None);
    }
    let Some((factory, ty, offset)) = (|| {
        let offset = address.get_offset().checked_sub(entry.entry_addr.get_offset())?;
        let offset = i32::try_from(offset).ok()?.checked_add(entry.symbol_offset)?;
        Some((fd.get_arch().types()?, entry.symbol_type?, offset))
    })() else { return Ok(None) };
    factory.get_exact_piece(ty, offset, width)
}

fn pointed_storage(fd: &Funcdata, mut id: VarnodeId, width: i32) -> Option<Rc<Datatype>> {
    let mut offset = 0i64;
    for _ in 0..32 {
        let value = fd.vbank().get(id)?;
        if value.is_type_lock() {
            return fd
                .get_arch()
                .types()?
                .get_exact_piece(
                    value.get_type().get_ptr_to()?,
                    i32::try_from(offset).ok()?,
                    width,
                )
                .ok()?;
        }
        let op = fd.obank().get(value.get_def()?)?;
        match op.code() {
            OpCode::CPUI_COPY | OpCode::CPUI_CAST => id = op.get_in(0)?,
            OpCode::CPUI_PTRSUB | OpCode::CPUI_INT_ADD => {
                let displacement = fd.vbank().get(op.get_in(1)?)?;
                if !displacement.is_constant() {
                    return None;
                }
                let scale = if op.code() == OpCode::CPUI_PTRSUB {
                    fd.vbank().get(op.get_in(0)?)?.get_type().get_word_size()? as i64
                } else {
                    1
                };
                offset =
                    offset.checked_add((displacement.get_offset() as i64).checked_mul(scale)?)?;
                id = op.get_in(0)?;
            }
            OpCode::CPUI_PTRADD => {
                let base = fd.vbank().get(op.get_in(0)?)?;
                let index = fd.vbank().get(op.get_in(1)?)?;
                let scale = fd.vbank().get(op.get_in(2)?)?;
                if !scale.is_constant() {
                    return None;
                }
                if scale.get_offset() != base.get_type().get_ptr_to()?.get_align_size() as u64 {
                    if !index.is_constant() {
                        return None;
                    }
                    offset = offset.checked_add(
                        (index.get_offset() as i64)
                            .checked_mul(i64::try_from(scale.get_offset()).ok()?)?,
                    )?;
                }
                id = op.get_in(0)?;
            }
            _ => return None,
        }
    }
    None
}

pub(crate) fn input_contract(fd: &Funcdata, id: OpId, slot: i32) -> KunaResult<Option<Rc<Datatype>>> {
    let Some(op) = fd.obank().get(id).filter(|op| !op.is_dead()) else { return Ok(None) };
    if op.is_marker() || op.is_return_copy() {
        return Ok(None);
    }
    let contract = match op.code() {
        OpCode::CPUI_CALL | OpCode::CPUI_CALLIND if slot > 0 => {
            let Some(index) = fd.get_call_specs_index(id) else { return Ok(None) };
            let spec = fd.get_call_specs(index);
            if !spec.proto().has_store() {
                return Ok(None);
            }
            let Some(param) = spec.proto().get_param(slot - 1) else { return Ok(None) };
            if !param.is_type_locked() {
                return Ok(None);
            }
            param.get_type().cloned()
        }
        OpCode::CPUI_COPY if slot == 0 => {
            let Some(out) = op.get_out().and_then(|id| fd.vbank().get(id)) else { return Ok(None) };
            if out.is_persist() {
                storage_type(fd, out.get_addr(), out.get_size())?
            } else if out.is_type_lock() {
                Some(out.get_type().clone())
            } else {
                return Ok(None);
            }
        }
        OpCode::CPUI_STORE if slot == 2 => {
            let Some((destination, width)) = (|| {
                Some((fd.vbank().get(op.get_in(1)?)?, fd.vbank().get(op.get_in(2)?)?.get_size()))
            })() else { return Ok(None) };
            if destination.is_constant() {
                let Some(space) = (|| {
                    let index = fd.vbank().get(op.get_in(0)?)?.get_offset();
                    fd.get_arch().manage().get_space(i32::try_from(index).ok()?)
                })() else { return Ok(None) };
                let address = Address::new(
                    space.clone(),
                    AddrSpace::address_to_byte(destination.get_offset(), space.get_word_size()),
                );
                storage_type(fd, &address, width)?
            } else {
                pointed_storage(fd, op.get_in(1).expect("store destination present"), width)
            }
        }
        OpCode::CPUI_CALLOTHER if slot == 2 => {
            let Some(code) = op.get_in(0).and_then(|id| fd.vbank().get(id)) else { return Ok(None) };
            if !code.is_constant() || code.get_offset() != BUILTIN_VOLATILE_WRITE as u64 {
                return Ok(None);
            }
            let Some((target, width)) = (|| {
                Some((fd.vbank().get(op.get_in(1)?)?, fd.vbank().get(op.get_in(2)?)?.get_size()))
            })() else { return Ok(None) };
            storage_type(fd, target.get_addr(), width)?
        }
        OpCode::CPUI_RETURN if slot == 1 && fd.get_func_proto().is_output_locked() => {
            fd.get_func_proto().get_output_type().cloned()
        }
        _ => return Ok(None),
    };
    Ok(contract)
}

pub(crate) fn declared_view(fd: &Funcdata, id: OpId, slot: i32) -> KunaResult<Option<Rc<Datatype>>> {
    let Some(pointer) = input_contract(fd, id, slot)? else { return Ok(None) };
    if pointer.get_metatype() != type_metatype::TYPE_PTR {
        return Ok(None);
    }
    Ok(pointer.get_ptr_to().filter(|view| !view.is_incomplete() && view.get_size() > 0))
}

pub(crate) fn prepare_casts(fd: &mut Funcdata, factory: &dyn TypeFactory) -> KunaResult<()> {
    let mut uses = Vec::new();
    for id in fd.obank().iter_alive() {
        let op = fd.obank().get(id).unwrap();
        if matches!(op.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
            continue;
        }
        for slot in 0..op.num_input() {
            if let Some(ty) = declared_view(fd, id, slot)? {
                uses.push((id, slot, ty));
            }
        }
    }
    for (id, slot, ty) in uses {
        let Some(point) = crate::kuna_stackobjects::SourcePoint::op(fd, id) else {
            continue;
        };
        if fd.stack_object_bound_uses.contains(&(point, slot)) {
            continue;
        }
        let Some(input) = fd.obank().get(id).and_then(|op| op.get_in(slot)) else {
            continue;
        };
        let Some(address) = crate::kuna_stackranges::frame_address(fd, input) else {
            continue;
        };
        if address.first != address.last || !address.terms.is_empty() {
            continue;
        }
        let Some(scope) = fd.get_scope_local() else {
            continue;
        };
        let at = Address::new(
            scope.get_space_id().clone(),
            scope.get_space_id().wrap_offset(address.first as u64),
        );
        let Some(info) =
            scope.query_container_for_link_width(&at, ty.get_size(), &Address::new_invalid())
        else {
            continue;
        };
        let Some(backing) = &info.sym_type else {
            continue;
        };
        if !backing.get_name().starts_with("stack_views_") {
            continue;
        }
        let member = (0..backing.num_depend()).find(|&i| {
            backing.get_depend(i).is_some_and(|view| {
                (info.sym_off == 0 && Rc::ptr_eq(&view, &ty))
                    || (view.get_name().starts_with("stack_slice_")
                        && view.get_field(0).is_some_and(|field| {
                            field.offset == info.sym_off && Rc::ptr_eq(&field.field_type, &ty)
                        }))
            })
        });
        let Some(member) = member else { continue };
        let width = fd.vbank().get(input).unwrap().get_size();
        if let Some(value) =
            crate::kuna_stackobjectasserts::backing_view(fd, id, width, &info, member, &ty, factory)
        {
            if fd.op_set_input(id, value, slot).is_ok() {
                fd.stack_object_bound_uses.insert((point, slot));
            }
        }
    }
    Ok(())
}
