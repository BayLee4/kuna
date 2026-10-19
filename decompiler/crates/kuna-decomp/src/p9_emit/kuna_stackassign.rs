//! Byte stores retain a user-declared layout across incompatible object views.

use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, Datatype};
use crate::funcdata::Funcdata;
use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_num::opcodes::OpCode;
use std::rc::Rc;

pub(crate) struct Assignment {
    pub output: VarnodeId,
    pub operand: Option<VarnodeId>,
    pub raw_constant: bool,
    pub datatype: Rc<Datatype>,
    pub size: i32,
    pub name: String,
    pub offset: i32,
    pub pointer_size: i32,
}

pub(crate) fn assignment(fd: &Funcdata, op: OpId) -> KunaResult<Option<Assignment>> {
    if !fd.get_arch().stack_views {
        return Ok(None);
    }
    let Some(operation) = fd.obank().get(op) else { return Ok(None) };
    if operation.is_marker() {
        return Ok(None);
    }
    let Some(output) = operation.get_out() else { return Ok(None) };
    let Some(value) = fd.vbank().get(output) else { return Ok(None) };
    let Some(stack) = fd.get_arch().manage().get_stack_space() else { return Ok(None) };
    if value.get_space().get_index() != stack.get_index() {
        return Ok(None);
    }
    let size = value.get_size();
    if !matches!(size, 1 | 2 | 4 | 8 | 16) {
        return Ok(None);
    }
    // A selected backing member owns this write, even when a smaller ABI
    // formal overlaps it. Keep both input materialization and native stores
    // on the bound member instead of reselecting the formal as their target.
    if fd.stack_write_views.get(&op).is_some_and(|view| {
        view.offset >= 0
            && i64::from(view.offset) + i64::from(size) <= i64::from(view.backing.get_size())
            && value
                .get_high()
                .and_then(|high| fd.high_bank().get(high))
                .is_some_and(|high| {
                    high.get_symbol_offset() == view.offset
                        && high.kuna_symbol_type().is_some_and(|backing| {
                            Rc::ptr_eq(backing, &view.backing)
                        })
                })
    }) {
        return Ok(None);
    }
    let Some(scope) = fd.get_scope_local() else { return Ok(None) };
    let Some(info) =
        scope.query_container_for_link_width(value.get_addr(), size, &Address::new_invalid()) else { return Ok(None) };
    let Some(root) = info.sym_type.as_ref() else { return Ok(None) };
    if !scope.database().symbol(info.symbol).is_type_locked()
        || info.is_name_undefined
        || root.get_name().starts_with("stack_views_")
        || !incompatible_views(fd, &info.entry_addr, root)
    {
        return Ok(None);
    }
    let operand = matches!(operation.code(), OpCode::CPUI_COPY | OpCode::CPUI_CAST)
        .then(|| operation.get_in(0))
        .flatten();
    let raw_constant = match operand {
        Some(id) if fd.vbank().get(id).is_some_and(|value| value.is_constant()) =>
            !crate::kuna_stackviews::pointer_origin(fd, id)?,
        _ => false,
    };
    let Some(factory) = fd.get_arch().types() else { return Ok(None) };
    let datatype = if raw_constant {
        factory.get_base(size, type_metatype::TYPE_UINT)?
    } else if let Some(input) = operand {
        let ty = if crate::kuna_stackviews::pointer_origin(fd, input)? {
            let read_type = fd.vn_type_read_facing(input, op)?;
            if read_type.get_metatype() == type_metatype::TYPE_PTR {
                read_type
            } else {
                factory
                    .get_type_pointer(size, factory.get_type_void()?, 1)?
            }
        } else {
            match crate::printc::declared_variable_type(fd, fd.get_arch().decl_high_type, input) {
                Some(ty) => ty,
                None => fd.vn_type_read_facing(input, op)?,
            }
        };
        if scalar(&ty) && ty.get_size() == size {
            ty
        } else {
            return Ok(None);
        }
    } else if crate::kuna_stackviews::pointer_origin(fd, output)? {
        factory
            .get_type_pointer(size, factory.get_type_void()?, 1)?
    } else {
        let ty = crate::typeop::type_op_info(operation.code())
            .get_output_local(factory, size)?;
        if !scalar(&ty) {
            return Ok(None);
        }
        ty
    };
    Ok(Some(Assignment {
        output,
        operand,
        raw_constant,
        datatype,
        size,
        name: info.display_name,
        offset: info.sym_off,
        pointer_size: stack.get_addr_size() as i32,
    }))
}

fn incompatible_views(fd: &Funcdata, address: &Address, root: &Rc<Datatype>) -> bool {
    let Some(factory) = fd.get_arch().types() else {
        return false;
    };
    crate::kuna_stackobjects::objects(fd).iter().any(|object| {
        if object.address.get_space().map(|space| space.get_index())
            != address.get_space().map(|space| space.get_index())
        {
            return false;
        }
        let offset = object
            .address
            .get_offset()
            .wrapping_sub(address.get_offset());
        if offset
            .checked_add(object.size as u64)
            .is_none_or(|end| end > root.get_size() as u64)
        {
            return false;
        }
        object.uses.iter().any(|use_| {
            let ty = crate::kuna_stackviews::scalar_piece(
                factory,
                Rc::clone(root),
                offset as i32,
                object.size,
            )
            .or_else(|| {
                factory
                    .get_exact_piece(Rc::clone(root), offset as i32, object.size)
                    .ok()
                    .flatten()
            });
            ty.is_none_or(|ty| {
                !Rc::ptr_eq(&ty, &use_.datatype)
                    && !(integer(&ty)
                        && integer(&use_.datatype)
                        && ty.get_size() == use_.datatype.get_size())
            })
        })
    })
}

fn integer(datatype: &Datatype) -> bool {
    matches!(
        datatype.get_metatype(),
        type_metatype::TYPE_INT | type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN
    )
}

fn scalar(datatype: &Datatype) -> bool {
    matches!(
        datatype.get_metatype(),
        type_metatype::TYPE_BOOL
            | type_metatype::TYPE_INT
            | type_metatype::TYPE_UINT
            | type_metatype::TYPE_UNKNOWN
            | type_metatype::TYPE_FLOAT
            | type_metatype::TYPE_PTR
    )
}
