use super::*;

// Algorithms borrow immutable generation bodies. Edges are IDs; only TypeRoot
// convenience boundaries retain graph owners. Alias-sensitive queries report
// absent/false for unresolved aliases; fallible algorithms propagate resolution
// errors. Nominal identity and presentation remain intact during encoding.

impl<'a> TypeRef<'a> {
    pub fn related(&self, id: TypeId) -> KunaResult<TypeRef<'a>> { self.graph.get(id) }

    fn node(&self, id: TypeId) -> TypeRef<'a> {
        self.graph.get(id).expect("published datatype edge belongs to its graph")
    }

    pub fn type_order_formal(&self, op: &TypeRef<'_>) -> KunaResult<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.type_order_formal(op); }
        let effective_other = op.effective()?;
        let op = &effective_other;
        if self.id == op.id {
            return Ok(0);
        }
        if self.metatype == type_metatype::TYPE_PARTIALUNION {
            return Ok(1);
        }
        if op.metatype == type_metatype::TYPE_PARTIALUNION {
            return Ok(-1);
        }
        if self.metatype == type_metatype::TYPE_BOOL {
            return Ok(1);
        }
        if op.metatype == type_metatype::TYPE_BOOL {
            return Ok(-1);
        }
        self.compare(op, 10)
    }

    pub fn type_order(&self, op: &TypeRef<'_>) -> KunaResult<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.type_order(op); }
        let effective_other = op.effective()?;
        let op = &effective_other;
        if self.id == op.id {
            return Ok(0);
        }
        self.compare(op, 10)
    }

    pub fn has_same_variable_base(&self, ct: &TypeRef<'_>) -> KunaResult<bool> {
        if !self.is_variable_length() {
            return Ok(false);
        }
        if !ct.is_variable_length() {
            return Ok(false);
        }
        Ok(self.id == ct.id || (self.get_id() != 0 && self.get_id() == ct.get_id() && self.name == ct.name))
    }

    pub fn num_depend(&self) -> int4 {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().map_or(0, |ty| ty.num_depend()); }
        match &self.data.kind {
            DatatypeKind::Pointer { .. } | DatatypeKind::PointerRel { .. } => 1,
            DatatypeKind::Array { .. } => 1,
            DatatypeKind::Struct { field, .. } => field.len() as int4,
            DatatypeKind::Union { field } => field.len() as int4,
            DatatypeKind::PartialUnion { .. } => 0,
            _ => 0,
        }
    }

    pub fn get_depend(&self, index: int4) -> Option<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_depend(index); }
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, .. } => Some(*ptrto),
            DatatypeKind::PointerRel { ptrto, .. } => Some(*ptrto),
            DatatypeKind::Array { arrayof, .. } => Some(*arrayof),
            DatatypeKind::Struct { field, .. } => {
                field.get(index as usize).map(|f| f.field_type)
            }
            DatatypeKind::Union { field } => {
                field.get(index as usize).map(|f| f.field_type)
            }
            _ => None,
        }
    }

    pub fn get_ptr_into(&self) -> KunaResult<Option<(TypeId, int4)>> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.get_ptr_into(); }
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, .. } => Ok(Some((*ptrto, 0))),
            DatatypeKind::PointerRel { ptrto, parent, offset, .. } => {
                let meta = self.node(*ptrto).get_metatype();
                if meta == type_metatype::TYPE_STRUCT || meta == type_metatype::TYPE_UNION {
                    Ok(Some((*ptrto, 0)))
                } else {
                    Ok(Some((*parent, *offset)))
                }
            }
            _ => Ok(None),
        }
    }

    pub fn get_partial_base(&self) -> Option<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_partial_base(); }
        match &self.data.kind {
            DatatypeKind::PartialStruct { container, .. } => Some(*container),
            DatatypeKind::PartialUnion { container, .. } => Some(*container),
            DatatypeKind::PartialEnum { parent, .. } => Some(*parent),
            _ => None,
        }
    }

    pub fn get_stripped(&self) -> Option<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_stripped(); }
        match &self.data.kind {
            DatatypeKind::PartialStruct { stripped, .. } => Some(*stripped),
            DatatypeKind::PartialUnion { stripped, .. } => Some(*stripped),
            DatatypeKind::PartialEnum { stripped, .. } => Some(*stripped),
            DatatypeKind::PointerRel { stripped, .. } => *stripped,
            _ => None,
        }
    }

    pub fn get_component_for_ptr(&self) -> Option<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_component_for_ptr(); }
        match &self.data.kind {
            DatatypeKind::PartialStruct { container, stripped, offset } => {
                if self.node(*container).get_metatype() == type_metatype::TYPE_ARRAY {
                    if let Some(eltype) = self.node(*container).get_array_base() {
                        if self.node(eltype).get_metatype() != type_metatype::TYPE_UNKNOWN
                            && (*offset % self.node(eltype).get_align_size()) == 0
                        {
                            return Some(eltype);
                        }
                    }
                }
                Some(*stripped)
            }
            _ => None,
        }
    }

    pub fn get_ptr_to(&self) -> Option<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_ptr_to(); }
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, .. } => Some(*ptrto),
            DatatypeKind::PointerRel { ptrto, .. } => Some(*ptrto),
            _ => None,
        }
    }

    pub fn get_word_size(&self) -> Option<uint4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_word_size(); }
        match &self.data.kind {
            DatatypeKind::Pointer { wordsize, .. } => Some(*wordsize),
            DatatypeKind::PointerRel { wordsize, .. } => Some(*wordsize),
            _ => None,
        }
    }

    pub fn spacebase_parts(&self) -> Option<(Option<Rc<AddrSpace>>, Address)> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.spacebase_parts(); }
        match &self.data.kind {
            DatatypeKind::Spacebase { spaceid, localframe } => {
                Some((spaceid.clone(), localframe.clone()))
            }
            _ => None,
        }
    }

    pub fn get_pointer_space(&self) -> Option<Rc<AddrSpace>> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_pointer_space(); }
        match &self.data.kind {
            DatatypeKind::Pointer { spaceid, .. } | DatatypeKind::PointerRel { spaceid, .. } => spaceid.clone(),
            _ => None,
        }
    }

    pub fn get_array_base(&self) -> Option<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_array_base(); }
        match &self.data.kind {
            DatatypeKind::Array { arrayof, .. } => Some(*arrayof),
            _ => None,
        }
    }

    pub fn num_elements(&self) -> Option<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.num_elements(); }
        match &self.data.kind {
            DatatypeKind::Array { arraysize, .. } => Some(*arraysize),
            _ => None,
        }
    }

    pub fn get_rel_parent(&self) -> Option<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_rel_parent(); }
        match &self.data.kind {
            DatatypeKind::PointerRel { parent, .. } => Some(*parent),
            _ => None,
        }
    }

    pub fn get_byte_offset(&self) -> Option<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_byte_offset(); }
        match &self.data.kind {
            DatatypeKind::PointerRel { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    pub fn get_address_offset(&self) -> Option<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_address_offset(); }
        match &self.data.kind {
            DatatypeKind::PointerRel { offset, wordsize, .. } => {
                Some(AddrSpace::byte_to_address_int(*offset as i64, *wordsize) as int4)
            }
            _ => None,
        }
    }

    pub fn spacebase_get_address(
        &self,
        off: uint8,
        mut sz: int4,
        point: &Address,
        manager: &kuna_base::space::AddrSpaceManager,
    ) -> Option<Address> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.spacebase_get_address(off, sz, point, manager); }
        let (spaceid, localframe) = self.as_spacebase()?;
        let spaceid = spaceid?;
        if localframe.is_invalid() {
            sz = -1;
        }
        let mut full_encoding: uint8 = 0;
        manager
            .resolve_constant(spaceid, off, sz, point, &mut full_encoding)
            .ok()
    }

    pub fn evaluate_thru_parent(&self, addr_off: u64) -> Option<bool> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.evaluate_thru_parent(addr_off); }
        match &self.data.kind {
            DatatypeKind::PointerRel { ptrto, wordsize, parent, offset, .. } => {
                let byte_off = AddrSpace::address_to_byte(addr_off, *wordsize);
                if self.node(*ptrto).get_metatype() == type_metatype::TYPE_STRUCT
                    && byte_off < self.node(*ptrto).get_size() as u64
                {
                    return Some(false);
                }
                let byte_off = byte_off
                    .wrapping_add(*offset as u64)
                    & kuna_base::address::calc_mask(self.get_size());
                Some(byte_off < self.node(*parent).get_size() as u64)
            }
            _ => None,
        }
    }

    pub fn get_partial_offset(&self) -> Option<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_partial_offset(); }
        match &self.data.kind {
            DatatypeKind::PartialStruct { offset, .. } => Some(*offset),
            DatatypeKind::PartialUnion { offset, .. } => Some(*offset),
            DatatypeKind::PartialEnum { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    pub fn compare(&self, op: &TypeRef<'_>, level: int4) -> KunaResult<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.compare(op, level); }
        let effective_other = op.effective()?;
        let op = &effective_other;
        match &self.data.kind {
            DatatypeKind::Alias => unreachable!("alias dispatched above"),
            DatatypeKind::Base | DatatypeKind::Void | DatatypeKind::Unknown => {
                Ok(self.compare_base(op))
            }
            DatatypeKind::Pointer { ptrto, spaceid, wordsize, .. } => {
                self.compare_pointer_body(op, level, ptrto, spaceid.as_ref(), *wordsize)
            }
            DatatypeKind::Array { arrayof, .. } => {
                let res = self.compare_base(op);
                if res != 0 {
                    return Ok(res);
                }
                let level = level - 1;
                if level < 0 {
                    if self.get_id() == op.get_id() {
                        return Ok(0);
                    }
                    return Ok(if self.get_id() < op.get_id() { -1 } else { 1 });
                }
                let op_arrayof = op
                    .get_array_base()
                    .ok_or_else(|| Self::array_invariant_err("compare"))?;
                self.node(*arrayof).compare(&op.node(op_arrayof), level)
            }
            DatatypeKind::Struct { field, bitfield } => {
                self.compare_struct(op, level, field, bitfield)
            }
            DatatypeKind::Union { field } => self.compare_union(op, level, field),
            DatatypeKind::Enum { .. } => self.compare_dependency(op),
            DatatypeKind::Code { proto } => self.compare_code(op, level, proto.as_ref()),
            DatatypeKind::Spacebase { .. } => self.compare_dependency(op),
            DatatypeKind::PartialStruct { container, offset, .. } => {
                self.compare_partial(op, level, container, *offset)
            }
            DatatypeKind::PartialUnion { container, offset, .. } => {
                self.compare_partial(op, level, container, *offset)
            }
            DatatypeKind::PartialEnum { parent, offset, .. } => {
                self.compare_partial(op, level, parent, *offset)
            }
            DatatypeKind::PointerRel { ptrto, spaceid, wordsize, stripped, .. } => {
                let res = self.compare_pointer_body(op, level, ptrto, spaceid.as_ref(), *wordsize)?;
                if res != 0 {
                    return Ok(res);
                }
                let (_, _, op_stripped, _, _) = op
                    .as_pointer_rel()
                    .ok_or_else(|| Self::pointer_invariant_err("compare(ptrrel)"))?;
                if stripped.is_none() {
                    if op_stripped.is_some() {
                        return Ok(-1);
                    }
                } else if op_stripped.is_none() {
                    return Ok(1);
                }
                Ok(0)
            }
        }
    }

    fn compare_struct(
        &self,
        op: &TypeRef<'_>,
        mut level: int4,
        field: &[TypeField],
        bitfield: &[TypeBitField],
    ) -> KunaResult<int4> {
        let res = self.compare_base(op);
        if res != 0 {
            return Ok(res);
        }
        let (op_field, op_bitfield) = op
            .as_struct_fields()
            .ok_or_else(|| Self::struct_invariant_err("compare"))?;
        if field.len() != op_field.len() {
            return Ok((op_field.len() as int4).wrapping_sub(field.len() as int4));
        }
        for (f1, f2) in field.iter().zip(op_field.iter()) {
            let cmp = f1.compare(self.graph, f2, op.graph);
            if cmp != 0 {
                return Ok(cmp);
            }
        }
        if bitfield.len() != op_bitfield.len() {
            return Ok((op_bitfield.len() as int4).wrapping_sub(bitfield.len() as int4));
        }
        for (b1, b2) in bitfield.iter().zip(op_bitfield.iter()) {
            let cmp = b1.compare(self.graph, b2, op.graph);
            if cmp != 0 {
                return Ok(cmp);
            }
        }
        level -= 1;
        if level < 0 {
            if self.get_id() == op.get_id() {
                return Ok(0);
            }
            return Ok(if self.get_id() < op.get_id() { -1 } else { 1 });
        }
        for (f1, f2) in field.iter().zip(op_field.iter()) {
            if !(f1.field_type == f2.field_type) {
                let c = self.node(f1.field_type).compare(&op.node(f2.field_type), level)?;
                if c != 0 {
                    return Ok(c);
                }
            }
        }
        for (b1, b2) in bitfield.iter().zip(op_bitfield.iter()) {
            if !(b1.field_type == b2.field_type) {
                let c = self.node(b1.field_type).compare(&op.node(b2.field_type), level)?;
                if c != 0 {
                    return Ok(c);
                }
            }
        }
        Ok(0)
    }

    fn compare_union(
        &self,
        op: &TypeRef<'_>,
        mut level: int4,
        field: &[TypeField],
    ) -> KunaResult<int4> {
        let res = self.compare_base(op);
        if res != 0 {
            return Ok(res);
        }
        let op_field = op
            .as_union_fields()
            .ok_or_else(|| Self::union_invariant_err("compare"))?;
        if field.len() != op_field.len() {
            return Ok((op_field.len() as int4).wrapping_sub(field.len() as int4));
        }
        for (f1, f2) in field.iter().zip(op_field.iter()) {
            if f1.name != f2.name {
                return Ok(if f1.name < f2.name { -1 } else { 1 });
            }
            if self.node(f1.field_type).get_metatype() != op.node(f2.field_type).get_metatype() {
                return Ok(if self.node(f1.field_type).get_metatype() < op.node(f2.field_type).get_metatype() {
                    -1
                } else {
                    1
                });
            }
        }
        level -= 1;
        if level < 0 {
            if self.get_id() == op.get_id() {
                return Ok(0);
            }
            return Ok(if self.get_id() < op.get_id() { -1 } else { 1 });
        }
        for (f1, f2) in field.iter().zip(op_field.iter()) {
            if !(f1.field_type == f2.field_type) {
                let c = self.node(f1.field_type).compare(&op.node(f2.field_type), level)?;
                if c != 0 {
                    return Ok(c);
                }
            }
        }
        Ok(0)
    }

    fn compare_code(
        &self,
        op: &TypeRef<'_>,
        mut level: int4,
        proto: Option<&crate::fspec::LogicalCallable>,
    ) -> KunaResult<int4> {
        let res = self.compare_base(op);
        if res != 0 {
            return Ok(res);
        }
        let op_proto = op
            .as_code_proto()
            .ok_or_else(|| Self::code_invariant_err("compare"))?;
        let res = Self::compare_code_basic(proto, op_proto)?;
        if res != 2 {
            return Ok(res);
        }
        level -= 1;
        if level < 0 {
            if self.get_id() == op.get_id() {
                return Ok(0);
            }
            return Ok(if self.get_id() < op.get_id() { -1 } else { 1 });
        }
        let proto = proto.ok_or_else(|| Self::code_invariant_err("compare"))?;
        let op_proto = op_proto.ok_or_else(|| Self::code_invariant_err("compare"))?;
        for (&param, &opparam) in proto.inputs.iter().zip(&op_proto.inputs) {
            let c = self.node(param).compare(&op.node(opparam), level)?;
            if c != 0 { return Ok(c); }
        }
        self.node(proto.output).compare(&op.node(op_proto.output), level)
    }

    fn compare_partial(
        &self,
        op: &TypeRef<'_>,
        mut level: int4,
        whole: &TypeId,
        offset: int4,
    ) -> KunaResult<int4> {
        let res = self.compare_base(op);
        if res != 0 {
            return Ok(res);
        }
        let (op_whole, op_offset) = op
            .as_partial_whole()
            .ok_or_else(|| Self::partial_invariant_err("compare"))?;
        if offset != op_offset {
            return Ok(if offset < op_offset { -1 } else { 1 });
        }
        level -= 1;
        if level < 0 {
            if self.get_id() == op.get_id() {
                return Ok(0);
            }
            return Ok(if self.get_id() < op.get_id() { -1 } else { 1 });
        }
        self.node(*whole).compare(&op.node(*op_whole), level)
    }

    fn as_plain_pointer(&self) -> Option<( &'a TypeId, Option<&'a Rc<AddrSpace>>, uint4)> {
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, spaceid, wordsize, .. } => {
                Some((ptrto, spaceid.as_ref(), *wordsize))
            }
            _ => None,
        }
    }

    fn as_any_pointer(&self) -> Option<( &'a TypeId, Option<&'a Rc<AddrSpace>>, uint4)> {
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, spaceid, wordsize, .. } => {
                Some((ptrto, spaceid.as_ref(), *wordsize))
            }
            DatatypeKind::PointerRel { ptrto, spaceid, wordsize, .. } => Some((ptrto, spaceid.as_ref(), *wordsize)),
            _ => None,
        }
    }

    fn as_pointer_rel(
        &self,
    ) -> Option<(&'a TypeId, uint4, Option<&'a TypeId>, &'a TypeId, int4)> {
        match &self.data.kind {
            DatatypeKind::PointerRel { ptrto, wordsize, stripped, parent, offset, .. } => {
                Some((ptrto, *wordsize, stripped.as_ref(), parent, *offset))
            }
            _ => None,
        }
    }

    fn compare_pointer_body(
        &self,
        op: &TypeRef<'_>,
        level: int4,
        ptrto: &TypeId,
        spaceid: Option<&Rc<AddrSpace>>,
        wordsize: uint4,
    ) -> KunaResult<int4> {
        let res = self.compare_base(op);
        if res != 0 {
            return Ok(res);
        }
        let (op_ptrto, op_spaceid, op_wordsize) = op
            .as_any_pointer()
            .ok_or_else(|| Self::pointer_invariant_err("compare"))?;
        if wordsize != op_wordsize {
            return Ok(if wordsize < op_wordsize { -1 } else { 1 });
        }
        if let Some(r) = Self::compare_pointer_space(spaceid, op_spaceid) {
            return Ok(r);
        }
        let level = level - 1;
        if level < 0 {
            if self.get_id() == op.get_id() {
                return Ok(0);
            }
            return Ok(if self.get_id() < op.get_id() { -1 } else { 1 });
        }
        self.node(*ptrto).compare(&op.node(*op_ptrto), level)
    }

    fn as_struct_fields(&self) -> Option<(&'a [TypeField], &'a [TypeBitField])> {
        match &self.data.kind {
            DatatypeKind::Struct { field, bitfield } => Some((field, bitfield)),
            _ => None,
        }
    }

    fn as_union_fields(&self) -> Option<&'a [TypeField]> {
        match &self.data.kind {
            DatatypeKind::Union { field } => Some(field),
            _ => None,
        }
    }

    fn as_code_proto(&self) -> Option<Option<&'a crate::fspec::LogicalCallable>> {
        match &self.data.kind {
            DatatypeKind::Code { proto } => Some(proto.as_ref()),
            _ => None,
        }
    }

    fn as_partial_whole(&self) -> Option<(&'a TypeId, int4)> {
        match &self.data.kind {
            DatatypeKind::PartialStruct { container, offset, .. } => Some((container, *offset)),
            DatatypeKind::PartialUnion { container, offset, .. } => Some((container, *offset)),
            DatatypeKind::PartialEnum { parent, offset, .. } => Some((parent, *offset)),
            _ => None,
        }
    }

    pub(crate) fn as_enum_namemap(&self) -> Option<&'a std::collections::BTreeMap<u64, String>> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.as_enum_namemap(); }
        match &self.data.kind {
            DatatypeKind::Enum { namemap } => Some(namemap),
            _ => None,
        }
    }

    fn as_spacebase(&self) -> Option<(Option<&'a Rc<AddrSpace>>, &'a Address)> {
        match &self.data.kind {
            DatatypeKind::Spacebase { spaceid, localframe } => {
                Some((spaceid.as_ref(), localframe))
            }
            _ => None,
        }
    }

    fn enum_invariant_err(method: &str) -> KunaError {
        KunaError::lowlevel(format!(
            "Datatype::{method}: enum override reached with non-enum op \
             (submeta invariant violated)"
        ))
    }

    fn spacebase_invariant_err(method: &str) -> KunaError {
        KunaError::lowlevel(format!(
            "Datatype::{method}: spacebase override reached with non-spacebase op \
             (submeta invariant violated)"
        ))
    }

    fn compare_spacebase_space(
        a: Option<&Rc<AddrSpace>>,
        b: Option<&Rc<AddrSpace>>,
    ) -> Option<int4> {
        match (a, b) {
            (None, None) => None,
            (None, Some(_)) => Some(-1),
            (Some(_), None) => Some(1),
            (Some(sa), Some(sb)) => {
                if Rc::ptr_eq(sa, sb) {
                    None
                } else {
                    let pa = Rc::as_ptr(sa) as usize;
                    let pb = Rc::as_ptr(sb) as usize;
                    Some(if pa < pb { -1 } else { 1 })
                }
            }
        }
    }

    fn struct_invariant_err(method: &str) -> KunaError {
        KunaError::lowlevel(format!(
            "Datatype::{method}: struct override reached with non-struct op \
             (submeta invariant violated)"
        ))
    }

    fn union_invariant_err(method: &str) -> KunaError {
        KunaError::lowlevel(format!(
            "Datatype::{method}: union override reached with non-union op \
             (submeta invariant violated)"
        ))
    }

    fn code_invariant_err(method: &str) -> KunaError {
        KunaError::lowlevel(format!(
            "Datatype::{method}: code override reached with non-code op \
             (submeta invariant violated)"
        ))
    }

    fn partial_invariant_err(method: &str) -> KunaError {
        KunaError::lowlevel(format!(
            "Datatype::{method}: partial override reached with non-partial op \
             (submeta invariant violated)"
        ))
    }

    fn compare_code_basic(proto: Option<&crate::fspec::LogicalCallable>, op_proto: Option<&crate::fspec::LogicalCallable>) -> KunaResult<int4> {
        let (a,b) = match (proto,op_proto) { (None,None)=>return Ok(0), (None,Some(_))=>return Ok(1), (Some(_),None)=>return Ok(-1), (Some(a),Some(b))=>(a,b) };
        let binding = a.binding.cmp(&b.binding);
        if binding != std::cmp::Ordering::Equal { return Ok(if binding.is_lt() {-1} else {1}); }
        if a.inputs.len() != b.inputs.len() { return Ok(if a.inputs.len() > b.inputs.len() {-1} else {1}); }
        let shape_a=(a.flags,a.variadic,a.input_closed,a.logical_first);
        let shape_b=(b.flags,b.variadic,b.input_closed,b.logical_first);
        match shape_a.cmp(&shape_b) { std::cmp::Ordering::Less=>Ok(-1), std::cmp::Ordering::Greater=>Ok(1), std::cmp::Ordering::Equal=>Ok(2) }
    }

    fn compare_pointer_space(
        a: Option<&Rc<AddrSpace>>,
        b: Option<&Rc<AddrSpace>>,
    ) -> Option<int4> {
        match (a, b) {
            (None, None) => None,
            (None, Some(_)) => Some(1),
            (Some(_), None) => Some(-1),
            (Some(sa), Some(sb)) => {
                if Rc::ptr_eq(sa, sb) {
                    None
                } else {
                    Some(if sa.get_index() < sb.get_index() { -1 } else { 1 })
                }
            }
        }
    }

    pub(super) fn compare_dependency_ptr(a: &TypeId, b: &TypeId) -> int4 {
        match a.cmp(b) { std::cmp::Ordering::Less => -1, std::cmp::Ordering::Equal => 0, std::cmp::Ordering::Greater => 1 }
    }

    fn pointer_invariant_err(method: &str) -> KunaError {
        KunaError::lowlevel(format!(
            "Datatype::{method}: pointer override reached with non-pointer op \
             (submeta invariant violated)"
        ))
    }

    fn array_invariant_err(method: &str) -> KunaError {
        KunaError::lowlevel(format!(
            "Datatype::{method}: array override reached with non-array op \
             (submeta invariant violated)"
        ))
    }

    fn compare_base(&self, op: &TypeRef<'_>) -> int4 {
        if self.submeta != op.submeta {
            return if self.submeta < op.submeta { -1 } else { 1 };
        }
        if self.size != op.size {
            return op.size.wrapping_sub(self.size);
        }
        0
    }

    pub fn compare_dependency(&self, op: &TypeRef<'_>) -> KunaResult<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.compare_dependency(op); }
        let effective_other = op.effective()?;
        let op = &effective_other;
        match &self.data.kind {
            DatatypeKind::Alias => unreachable!("alias dispatched above"),
            DatatypeKind::Base | DatatypeKind::Void | DatatypeKind::Unknown => {
                Ok(self.compare_dependency_base(op))
            }
            DatatypeKind::Pointer { ptrto, spaceid, wordsize, .. } => {
                if self.submeta != op.get_sub_meta() {
                    return Ok(if self.submeta < op.get_sub_meta() { -1 } else { 1 });
                }
                let (op_ptrto, op_spaceid, op_wordsize) = op
                    .as_plain_pointer()
                    .ok_or_else(|| Self::pointer_invariant_err("compareDependency"))?;
                let ptr_cmp = Self::compare_dependency_ptr(ptrto, op_ptrto);
                if ptr_cmp != 0 {
                    return Ok(ptr_cmp);
                }
                if *wordsize != op_wordsize {
                    return Ok(if *wordsize < op_wordsize { -1 } else { 1 });
                }
                if let Some(r) = Self::compare_pointer_space(spaceid.as_ref(), op_spaceid) {
                    return Ok(r);
                }
                Ok(op.get_size().wrapping_sub(self.size))
            }
            DatatypeKind::Array { arrayof, .. } => {
                if self.submeta != op.get_sub_meta() {
                    return Ok(if self.submeta < op.get_sub_meta() { -1 } else { 1 });
                }
                let op_arrayof = op
                    .get_array_base()
                    .ok_or_else(|| Self::array_invariant_err("compareDependency"))?;
                let arr_cmp = Self::compare_dependency_ptr(arrayof, &op_arrayof);
                if arr_cmp != 0 {
                    return Ok(arr_cmp);
                }
                Ok(op.get_size().wrapping_sub(self.size))
            }
            DatatypeKind::Struct { field, bitfield } => {
                self.compare_dependency_struct(op, field, bitfield)
            }
            DatatypeKind::Union { field } => self.compare_dependency_union(op, field),
            DatatypeKind::Enum { namemap } => self.compare_dependency_enum(op, namemap),
            DatatypeKind::Code { proto } => self.compare_dependency_code(op, proto.as_ref()),
            DatatypeKind::Spacebase { spaceid, localframe } => {
                self.compare_dependency_spacebase(op, spaceid.as_ref(), localframe)
            }
            DatatypeKind::PartialStruct { container, offset, .. } => {
                self.compare_dependency_partial(op, container, *offset)
            }
            DatatypeKind::PartialUnion { container, offset, .. } => {
                self.compare_dependency_partial(op, container, *offset)
            }
            DatatypeKind::PartialEnum { parent, offset, .. } => {
                self.compare_dependency_partial(op, parent, *offset)
            }
            DatatypeKind::PointerRel { ptrto, spaceid, wordsize, parent, offset, .. } => {
                if self.submeta != op.get_sub_meta() {
                    return Ok(if self.submeta < op.get_sub_meta() { -1 } else { 1 });
                }
                let (op_ptrto, op_wordsize, _, op_parent, op_offset) = op
                    .as_pointer_rel()
                    .ok_or_else(|| Self::pointer_invariant_err("compareDependency(ptrrel)"))?;
                let ptr_cmp = Self::compare_dependency_ptr(ptrto, op_ptrto);
                if ptr_cmp != 0 {
                    return Ok(ptr_cmp);
                }
                if *offset != op_offset {
                    return Ok(if *offset < op_offset { -1 } else { 1 });
                }
                let par_cmp = Self::compare_dependency_ptr(parent, op_parent);
                if par_cmp != 0 {
                    return Ok(par_cmp);
                }
                if *wordsize != op_wordsize {
                    return Ok(if *wordsize < op_wordsize { -1 } else { 1 });
                }
                if let Some(r) = Self::compare_pointer_space(spaceid.as_ref(), op.get_pointer_space().as_ref()) {
                    return Ok(r);
                }
                Ok(op.get_size().wrapping_sub(self.size))
            }
        }
    }

    fn compare_dependency_struct(
        &self,
        op: &TypeRef<'_>,
        field: &[TypeField],
        bitfield: &[TypeBitField],
    ) -> KunaResult<int4> {
        let res = self.compare_dependency_base(op);
        if res != 0 {
            return Ok(res);
        }
        let (op_field, op_bitfield) = op
            .as_struct_fields()
            .ok_or_else(|| Self::struct_invariant_err("compareDependency"))?;
        if field.len() != op_field.len() {
            return Ok((op_field.len() as int4).wrapping_sub(field.len() as int4));
        }
        for (f1, f2) in field.iter().zip(op_field.iter()) {
            let cmp = f1.compare_dependency(f2);
            if cmp != 0 {
                return Ok(cmp);
            }
        }
        if bitfield.len() != op_bitfield.len() {
            return Ok((op_bitfield.len() as int4).wrapping_sub(bitfield.len() as int4));
        }
        for (b1, b2) in bitfield.iter().zip(op_bitfield.iter()) {
            let cmp = b1.compare_dependency(b2);
            if cmp != 0 {
                return Ok(cmp);
            }
        }
        Ok(0)
    }

    fn compare_dependency_union(&self, op: &TypeRef<'_>, field: &[TypeField]) -> KunaResult<int4> {
        let res = self.compare_dependency_base(op);
        if res != 0 {
            return Ok(res);
        }
        let op_field = op
            .as_union_fields()
            .ok_or_else(|| Self::union_invariant_err("compareDependency"))?;
        if field.len() != op_field.len() {
            return Ok((op_field.len() as int4).wrapping_sub(field.len() as int4));
        }
        for (f1, f2) in field.iter().zip(op_field.iter()) {
            if f1.name != f2.name {
                return Ok(if f1.name < f2.name { -1 } else { 1 });
            }
            let cmp = Self::compare_dependency_ptr(&f1.field_type, &f2.field_type);
            if cmp != 0 {
                return Ok(cmp);
            }
        }
        Ok(0)
    }

    fn compare_dependency_enum(
        &self,
        op: &TypeRef<'_>,
        namemap: &std::collections::BTreeMap<u64, String>,
    ) -> KunaResult<int4> {
        let res = self.compare_dependency_base(op);
        if res != 0 {
            return Ok(res);
        }
        let op_namemap = op
            .as_enum_namemap()
            .ok_or_else(|| Self::enum_invariant_err("compareDependency"))?;
        if namemap.len() != op_namemap.len() {
            return Ok(if namemap.len() < op_namemap.len() { -1 } else { 1 });
        }
        for ((v1, n1), (v2, n2)) in namemap.iter().zip(op_namemap.iter()) {
            if v1 != v2 {
                return Ok(if v1 < v2 { -1 } else { 1 });
            }
            if n1 != n2 {
                return Ok(if n1 < n2 { -1 } else { 1 });
            }
        }
        Ok(0)
    }

    fn compare_dependency_code(
        &self,
        op: &TypeRef<'_>,
        proto: Option<&crate::fspec::LogicalCallable>,
    ) -> KunaResult<int4> {
        let res = self.compare_dependency_base(op);
        if res != 0 {
            return Ok(res);
        }
        let op_proto = op
            .as_code_proto()
            .ok_or_else(|| Self::code_invariant_err("compareDependency"))?;
        let res = Self::compare_code_basic(proto, op_proto)?;
        if res != 2 {
            return Ok(res);
        }
        let proto = proto.ok_or_else(|| Self::code_invariant_err("compareDependency"))?;
        let op_proto =
            op_proto.ok_or_else(|| Self::code_invariant_err("compareDependency"))?;
        for (param, opparam) in proto.inputs.iter().zip(&op_proto.inputs) {
            let c = Self::compare_dependency_ptr(param, opparam);
            if c != 0 { return Ok(c); }
        }
        Ok(Self::compare_dependency_ptr(&proto.output, &op_proto.output))
    }

    fn compare_dependency_spacebase(
        &self,
        op: &TypeRef<'_>,
        spaceid: Option<&Rc<AddrSpace>>,
        localframe: &Address,
    ) -> KunaResult<int4> {
        let res = self.compare_dependency_base(op);
        if res != 0 {
            return Ok(res);
        }
        let (op_spaceid, op_localframe) = op
            .as_spacebase()
            .ok_or_else(|| Self::spacebase_invariant_err("compareDependency"))?;
        if let Some(r) = Self::compare_spacebase_space(spaceid, op_spaceid) {
            return Ok(r);
        }
        if localframe.is_invalid() {
            return Ok(0);
        }
        if localframe != op_localframe {
            return Ok(if localframe < op_localframe { -1 } else { 1 });
        }
        Ok(0)
    }

    fn compare_dependency_partial(
        &self,
        op: &TypeRef<'_>,
        whole: &TypeId,
        offset: int4,
    ) -> KunaResult<int4> {
        if self.submeta != op.get_sub_meta() {
            return Ok(if self.submeta < op.get_sub_meta() { -1 } else { 1 });
        }
        let (op_whole, op_offset) = op
            .as_partial_whole()
            .ok_or_else(|| Self::partial_invariant_err("compareDependency"))?;
        let cmp = Self::compare_dependency_ptr(whole, op_whole);
        if cmp != 0 {
            return Ok(cmp);
        }
        if offset != op_offset {
            return Ok(if offset < op_offset { -1 } else { 1 });
        }
        Ok(op.get_size().wrapping_sub(self.size))
    }

    fn compare_dependency_base(&self, op: &TypeRef<'_>) -> int4 {
        if self.submeta != op.submeta {
            return if self.submeta < op.submeta { -1 } else { 1 };
        }
        if self.size != op.size {
            return op.size.wrapping_sub(self.size);
        }
        0
    }

    fn get_field_iter(&self, field: &[TypeField], off: int4) -> int4 {
        let mut min: int4 = 0;
        let mut max: int4 = field.len() as int4 - 1;
        while min <= max {
            let mid = (min + max) / 2;
            let curfield = &field[mid as usize];
            if curfield.offset > off {
                max = mid - 1;
            } else {
                if curfield.offset + self.node(curfield.field_type).get_size() > off {
                    return mid;
                }
                min = mid + 1;
            }
        }
        -1
    }

    fn get_lower_bound_field(field: &[TypeField], off: int4) -> int4 {
        if field.is_empty() {
            return -1;
        }
        let mut min: int4 = 0;
        let mut max: int4 = field.len() as int4 - 1;
        while min < max {
            let mid = (min + max + 1) / 2;
            if field[mid as usize].offset > off {
                max = mid - 1;
            } else {
                min = mid;
            }
        }
        if min == max && field[min as usize].offset <= off {
            return min;
        }
        -1
    }

    fn upper_bound_idx<T>(slice: &[T], value: int4, comp: impl Fn(int4, &T) -> bool) -> usize {
        let mut first: usize = 0;
        let mut count = slice.len();
        while count > 0 {
            let step = count / 2;
            let it = first + step;
            if !comp(value, &slice[it]) {
                first = it + 1;
                count -= step + 1;
            } else {
                count = step;
            }
        }
        first
    }

    pub fn collect_bit_fields(
        &self,
        base_offset: int4,
        res: &mut Vec<BitFieldTriple>,
        offset: int4,
        sz: int4,
    ) {
        if matches!(self.data.kind, DatatypeKind::Alias) {
            if let Ok(ty) = self.effective() { ty.collect_bit_fields(base_offset, res, offset, sz); }
            return;
        }
        let (field, bitfield) = match self.as_struct_fields() {
            Some(pair) => pair,
            None => return,
        };
        let start = Self::upper_bound_idx(bitfield, offset, TypeBitField::compare_max_byte);
        if start != bitfield.len() {
            let range = BitRange::byte_range(offset, sz, bitfield[start].is_big_endian);
            for cur_bit_field in &bitfield[start..] {
                let code = cur_bit_field.bits().overlap_test(&range);
                if code == 1 {
                    break;
                }
                if code == -1 {
                    continue;
                }
                res.push(BitFieldTriple::new(cur_bit_field.clone(), base_offset));
            }
        }
        let fstart = Self::upper_bound_idx(field, offset, |off, field| field.compare_max_byte(self.graph, off));
        for cur_field in &field[fstart..] {
            if cur_field.offset >= offset + sz {
                break;
            }
            if self.node(cur_field.field_type).get_metatype() != type_metatype::TYPE_STRUCT {
                continue;
            }
            if !self.node(cur_field.field_type).has_bitfields() {
                continue;
            }
            self.node(cur_field.field_type).collect_bit_fields(
                base_offset + cur_field.offset,
                res,
                offset - cur_field.offset,
                sz,
            );
        }
    }

    pub fn has_bit_fields_in_range(&self, offset: int4, sz: int4) -> bool {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().is_ok_and(|ty| ty.has_bit_fields_in_range(offset, sz)); }
        let (field, bitfield) = match self.as_struct_fields() {
            Some(pair) => pair,
            None => return false,
        };
        let start = Self::upper_bound_idx(bitfield, offset, TypeBitField::compare_max_byte);
        if start != bitfield.len() {
            let range = BitRange::byte_range(offset, sz, bitfield[start].is_big_endian);
            for cur_bit_field in &bitfield[start..] {
                let code = cur_bit_field.bits().overlap_test(&range);
                if code == 1 {
                    break;
                }
                if code == -1 {
                    continue;
                }
                return true;
            }
        }
        let fstart = Self::upper_bound_idx(field, offset, |off, field| field.compare_max_byte(self.graph, off));
        for cur_field in &field[fstart..] {
            if cur_field.offset >= offset + sz {
                break;
            }
            if self.node(cur_field.field_type).get_metatype() != type_metatype::TYPE_STRUCT {
                continue;
            }
            if !self.node(cur_field.field_type).has_bitfields() {
                continue;
            }
            if self.node(cur_field.field_type).has_bit_fields_in_range(offset - cur_field.offset, sz)
            {
                return true;
            }
        }
        false
    }

    pub fn find_matching_bit_field(&self, range: &BitRange) -> Option<TypeBitField> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.find_matching_bit_field(range); }
        let (_field, bitfield) = self.as_struct_fields()?;
        let mut min: int4 = 0;
        let mut max: int4 = bitfield.len() as int4 - 1;
        while min <= max {
            let mid = (min + max) / 2;
            let cur = &bitfield[mid as usize];
            let code = range.overlap_test(&cur.bits());
            if code == 0 {
                return Some(cur.clone());
            }
            if code == -1 {
                max = mid - 1;
            } else if code == 1 {
                min = mid + 1;
            } else {
                break;
            }
        }
        None
    }

    pub fn get_sub_type(&self, off: int8) -> KunaResult<(Option<TypeId>, int8)> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.get_sub_type(off); }
        match &self.data.kind {
            DatatypeKind::Alias => unreachable!("alias dispatched above"),
            DatatypeKind::Base
            | DatatypeKind::Void
            | DatatypeKind::Unknown
            | DatatypeKind::Enum { .. }
            | DatatypeKind::Union { .. } => Ok((None, off)),
            DatatypeKind::Pointer { truncate, .. } => {
                if let Some(trunc) = truncate {
                    let min: int8 = if (self.flags & flags::truncate_bigendian) != 0 {
                        (self.size - self.node(*trunc).get_size()) as int8
                    } else {
                        0
                    };
                    if off >= min && off < min + self.node(*trunc).get_size() as int8 {
                        return Ok((Some(*trunc), off - min));
                    }
                }
                Ok((None, off))
            }
            DatatypeKind::Array { arrayof, .. } => {
                if off >= self.size as int8 {
                    return Ok((None, off));
                }
                let newoff = off % self.node(*arrayof).get_align_size() as int8;
                Ok((Some(*arrayof), newoff))
            }
            DatatypeKind::Struct { field, .. } => {
                let i = self.get_field_iter(field, off as int4);
                if i < 0 {
                    return Ok((None, off));
                }
                let curfield = &field[i as usize];
                let newoff = off - curfield.offset as int8;
                Ok((Some(curfield.field_type), newoff))
            }
            DatatypeKind::PartialStruct { container, offset, .. } => {
                let size_left: int8 = self.size as int8 - off;
                let mut off = off + *offset as int8;
                let mut ct = *container;
                loop {
                    let (next, newoff) = self.node(ct).get_sub_type(off)?;
                    match next {
                        None => return Ok((None, newoff)),
                        Some(next_ct) => {
                            off = newoff;
                            ct = next_ct;
                            if (self.node(ct).get_size() as int8 - off) <= size_left {
                                break;
                            }
                        }
                    }
                }
                Ok((Some(ct), off))
            }
            DatatypeKind::Code { .. } => Err(KunaError::lowlevel(
                "TypeCode::get_sub_type requires TypeFactory::get_base",
            )),
            DatatypeKind::Spacebase { .. } => Err(KunaError::lowlevel(
                "TypeSpacebase::getSubType needs symbol-table Scope resolution",
            )),
            DatatypeKind::PointerRel { .. }
            | DatatypeKind::PartialUnion { .. }
            | DatatypeKind::PartialEnum { .. } => Ok((None, off)),
        }
    }

    pub fn get_hole_size(&self, off: int4) -> KunaResult<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.get_hole_size(off); }
        match &self.data.kind {
            DatatypeKind::Array { arrayof, .. } => {
                let new_off = off % self.node(*arrayof).get_align_size();
                self.node(*arrayof).get_hole_size(new_off)
            }
            DatatypeKind::Struct { field, .. } => {
                let mut i = Self::get_lower_bound_field(field, off);
                if i >= 0 {
                    let curfield = &field[i as usize];
                    let new_off = off - curfield.offset;
                    if new_off < self.node(curfield.field_type).get_size() {
                        return self.node(curfield.field_type).get_hole_size(new_off);
                    }
                }
                i += 1;
                if (i as usize) < field.len() {
                    return Ok(field[i as usize].offset - off);
                }
                Ok(self.size - off)
            }
            DatatypeKind::PartialStruct { container, offset, .. } => {
                let size_left = self.size - off;
                let off = off + *offset;
                let mut res = self.node(*container).get_hole_size(off)?;
                if res > size_left {
                    res = size_left;
                }
                Ok(res)
            }
            _ => Ok(0),
        }
    }

    pub fn nearest_arrayed_component_forward(
        &self,
        off: int8,
        max: int8,
    ) -> KunaResult<(int8, int8, int8)> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.nearest_arrayed_component_forward(off, max); }
        match &self.data.kind {
            DatatypeKind::Array { arrayof, .. } => {
                let _ = max;
                if off > 0 {
                    return Ok((-1, off, 0));
                }
                let new_off = off;
                let el_size = self.node(*arrayof).get_align_size() as int8;
                Ok((-off, new_off, el_size))
            }
            DatatypeKind::Struct { field, .. } => {
                let mut i = Self::get_lower_bound_field(field, off as int4);
                let mut remain: int8;
                if i < 0 {
                    i += 1;
                    remain = 0;
                } else {
                    remain = off - field[i as usize].offset as int8;
                }
                while (i as usize) < field.len() {
                    let subfield = &field[i as usize];
                    let diff = subfield.offset as int8 - off;
                    if diff + remain > max {
                        break;
                    }
                    let (distance, _suboff, sub_el) =
                        self.node(subfield.field_type).nearest_arrayed_component_forward(remain, max)?;
                    if distance >= 0 {
                        let distance = diff + remain + distance;
                        if distance > max {
                            break;
                        }
                        return Ok((distance, -diff, sub_el));
                    }
                    i += 1;
                    remain = 0;
                }
                Ok((-1, off, 0))
            }
            DatatypeKind::Spacebase { .. } => Err(KunaError::lowlevel(
                "TypeSpacebase::nearestArrayedComponentForward needs Scope resolution",
            )),
            _ => Ok((-1, off, 0)),
        }
    }

    pub fn nearest_arrayed_component_backward(
        &self,
        off: int8,
        max: int8,
    ) -> KunaResult<(int8, int8, int8)> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.nearest_arrayed_component_backward(off, max); }
        match &self.data.kind {
            DatatypeKind::Array { arrayof, .. } => {
                let _ = max;
                if off < 0 {
                    return Ok((-1, off, 0));
                }
                let new_off = off;
                let el_size = self.node(*arrayof).get_align_size() as int8;
                let size = self.size as int8;
                let dist = if off <= size { size - off } else { off - size };
                Ok((dist, new_off, el_size))
            }
            DatatypeKind::Struct { field, .. } => {
                let first_index = Self::get_lower_bound_field(field, off as int4);
                let mut i = first_index;
                while i >= 0 {
                    let subfield = &field[i as usize];
                    let diff = off - subfield.offset as int8;
                    let subtype = &subfield.field_type;
                    let remain: int8 = if i == first_index {
                        diff
                    } else {
                        self.node(*subtype).get_size() as int8
                    };
                    if diff - remain > max {
                        break;
                    }
                    let (distance, _suboff, el_size) =
                        self.node(*subtype).nearest_arrayed_component_backward(remain, max)?;
                    if distance >= 0 {
                        let distance = (diff - remain) + distance;
                        if distance > max {
                            break;
                        }
                        return Ok((distance, diff, el_size));
                    }
                    i -= 1;
                }
                Ok((-1, off, 0))
            }
            DatatypeKind::Spacebase { .. } => Err(KunaError::lowlevel(
                "TypeSpacebase::nearestArrayedComponentBackward needs Scope resolution",
            )),
            _ => Ok((-1, off, 0)),
        }
    }

    pub(crate) fn test_for_array_slack(dt: &TypeRef<'_>, off: int8) -> KunaResult<bool> {
        if dt.get_metatype() == type_metatype::TYPE_ARRAY {
            return Ok(true);
        }
        if off < 0 {
            let (dist, _newoff, _el) = dt.nearest_arrayed_component_forward(off, 128)?;
            Ok(dist >= 0)
        } else {
            let (dist, _newoff, _el) = dt.nearest_arrayed_component_backward(off, 128)?;
            Ok(dist >= 0)
        }
    }

    pub fn is_ptrsub_matching(&self, off: int8, extra: int8, multiplier: int8) -> KunaResult<bool> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.is_ptrsub_matching(off, extra, multiplier); }
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, wordsize, .. } => {
                self.is_ptrsub_matching_pointer(ptrto, *wordsize, off, extra, multiplier)
            }
            DatatypeKind::PointerRel { ptrto, wordsize, stripped, parent, offset, .. } => {
                if stripped.is_some() {
                    return self.is_ptrsub_matching_pointer(
                        ptrto, *wordsize, off, extra, multiplier,
                    );
                }
                let i_off = AddrSpace::address_to_byte_int(off, *wordsize);
                let extra = AddrSpace::address_to_byte_int(extra, *wordsize);
                let i_off = i_off + *offset as int8 + extra;
                Ok(i_off >= 0 && i_off <= self.node(*parent).get_size() as int8)
            }
            _ => Ok(false),
        }
    }

    fn is_ptrsub_matching_pointer(
        &self,
        ptrto: &TypeId,
        wordsize: uint4,
        off: int8,
        extra: int8,
        multiplier: int8,
    ) -> KunaResult<bool> {
        let wordsize = &wordsize;
        let mut extra = extra;
        let mut multiplier = multiplier;
        let meta = self.node(*ptrto).get_metatype();
        match meta {
            type_metatype::TYPE_SPACEBASE => {
                let new_off = AddrSpace::address_to_byte_int(off, *wordsize);
                let (sub, new_off2) = self.node(*ptrto).get_sub_type(new_off)?;
                let sub_type = match sub {
                    Some(s) if new_off2 == 0 => s,
                    _ => return Ok(false),
                };
                extra = AddrSpace::address_to_byte_int(extra, *wordsize);
                if (extra < 0 || extra >= self.node(sub_type).get_size() as int8)
                    && !Self::test_for_array_slack(&self.node(sub_type), extra)?
                {
                    return Ok(false);
                }
            }
            type_metatype::TYPE_ARRAY => {
                if off != 0 {
                    return Ok(false);
                }
                multiplier = AddrSpace::address_to_byte_int(multiplier, *wordsize);
                if multiplier >= self.node(*ptrto).get_align_size() as int8 {
                    return Ok(false);
                }
            }
            type_metatype::TYPE_STRUCT => {
                let typesize = self.node(*ptrto).get_size() as int8;
                multiplier = AddrSpace::address_to_byte_int(multiplier, *wordsize);
                if multiplier >= self.node(*ptrto).get_align_size() as int8 {
                    return Ok(false);
                }
                let new_off = AddrSpace::address_to_byte_int(off, *wordsize);
                extra = AddrSpace::address_to_byte_int(extra, *wordsize);
                let (sub, new_off2) = self.node(*ptrto).get_sub_type(new_off)?;
                match sub {
                    Some(sub_type) => {
                        if new_off2 != 0 {
                            return Ok(false);
                        }
                        if (extra < 0 || extra >= self.node(sub_type).get_size() as int8)
                            && !Self::test_for_array_slack(&self.node(sub_type), extra)?
                        {
                            return Ok(false);
                        }
                    }
                    None => {
                        extra += new_off2;
                        if (extra < 0 || extra >= typesize) && typesize != 0 {
                            return Ok(false);
                        }
                    }
                }
            }
            type_metatype::TYPE_UNION => {
                return Ok(false);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn is_primitive_whole(&self) -> bool {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().is_ok_and(|ty| ty.is_primitive_whole()); }
        if !self.is_piece_structured() {
            return true;
        }
        let is_struct_or_array = self.metatype == type_metatype::TYPE_ARRAY
            || self.metatype == type_metatype::TYPE_STRUCT;
        if is_struct_or_array && self.num_depend() > 0 {
            if let Some(component) = self.get_depend(0) {
                if self.node(component).get_size() == self.get_size() {
                    return self.node(component).is_primitive_whole();
                }
            }
        }
        false
    }

    pub fn resolve_in_flow(
        &self,
        _op: crate::context::OpId,
        _slot: int4,
    ) -> KunaResult<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) {
            let effective = self.effective()?;
            let resolved = effective.resolve_in_flow(_op, _slot)?;
            return Ok(if resolved == effective.id { self.id } else { resolved });
        }
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, .. } => {
                if self.node(*ptrto).get_metatype() == type_metatype::TYPE_UNION {
                    Err(KunaError::lowlevel(
                        "TypePointer::resolveInFlow (pointer-to-union) needs \
                         Funcdata union-field resolution",
                    ))
                } else {
                    Ok(self.id)
                }
            }
            DatatypeKind::Array { .. } => Err(KunaError::lowlevel(
                "TypeArray::resolveInFlow needs Funcdata union-field scoring",
            )),
            DatatypeKind::Struct { .. }
            | DatatypeKind::Union { .. }
            | DatatypeKind::PartialUnion { .. } => Err(KunaError::lowlevel(
                "Datatype::resolveInFlow requires Funcdata union-field resolution",
            )),
            _ => Ok(self.id),
        }
    }

    pub fn find_resolve(
        &self,
        _op: crate::context::OpId,
        _slot: int4,
    ) -> KunaResult<TypeId> {
        if matches!(self.data.kind, DatatypeKind::Alias) {
            let effective = self.effective()?;
            let resolved = effective.find_resolve(_op, _slot)?;
            return Ok(if resolved == effective.id { self.id } else { resolved });
        }
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, .. } => {
                if self.node(*ptrto).get_metatype() == type_metatype::TYPE_UNION {
                    Err(KunaError::lowlevel(
                        "TypePointer::findResolve (pointer-to-union) needs \
                         Funcdata union-field cache",
                    ))
                } else {
                    Ok(self.id)
                }
            }
            DatatypeKind::Array { .. } => Err(KunaError::lowlevel(
                "TypeArray::findResolve needs Funcdata union-field cache",
            )),
            DatatypeKind::Struct { .. }
            | DatatypeKind::Union { .. }
            | DatatypeKind::PartialUnion { .. } => Err(KunaError::lowlevel(
                "Datatype::findResolve requires Funcdata union-field resolution",
            )),
            _ => Ok(self.id),
        }
    }

    pub fn find_compatible_resolve(&self, ct: &TypeRef<'_>) -> KunaResult<int4> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.find_compatible_resolve(ct); }
        let effective_other = ct.effective()?;
        let ct = &effective_other;
        match &self.data.kind {
            DatatypeKind::Pointer { ptrto, .. } | DatatypeKind::PointerRel { ptrto, .. } => {
                if ct.get_metatype() == type_metatype::TYPE_PTR {
                    let ct_ptrto = ct
                        .get_ptr_to()
                        .ok_or_else(|| Self::pointer_invariant_err("findCompatibleResolve"))?;
                    return self.node(*ptrto).find_compatible_resolve(&ct.node(ct_ptrto));
                }
                Ok(-1)
            }
            DatatypeKind::Array { arrayof, .. } => {
                if ct.needs_resolution()
                    && !self.node(*arrayof).needs_resolution()
                    && ct.find_compatible_resolve(&self.node(*arrayof))? >= 0
                {
                    return Ok(0);
                }
                if *arrayof == ct.id {
                    return Ok(0);
                }
                Ok(-1)
            }
            DatatypeKind::Struct { field, .. } => {
                let field_type = &field[0].field_type;
                if ct.needs_resolution()
                    && !self.node(*field_type).needs_resolution()
                    && ct.find_compatible_resolve(&self.node(*field_type))? >= 0
                {
                    return Ok(0);
                }
                if *field_type == ct.id {
                    return Ok(0);
                }
                Ok(-1)
            }
            DatatypeKind::Union { field } => {
                if !ct.needs_resolution() {
                    for (i, f) in field.iter().enumerate() {
                        if f.field_type == ct.id
                            && f.offset == 0
                        {
                            return Ok(i as int4);
                        }
                    }
                } else {
                    for (i, f) in field.iter().enumerate() {
                        if f.offset != 0 {
                            continue;
                        }
                        let field_type = &f.field_type;
                        if self.node(*field_type).get_size() != ct.get_size() {
                            continue;
                        }
                        if self.node(*field_type).needs_resolution() {
                            continue;
                        }
                        if ct.find_compatible_resolve(&self.node(*field_type))? >= 0 {
                            return Ok(i as int4);
                        }
                    }
                }
                Ok(-1)
            }
            DatatypeKind::PartialUnion { container, .. } => {
                self.node(*container).find_compatible_resolve(ct)
            }
            _ => Ok(-1),
        }
    }

    pub fn get_field(&self, i: int4) -> Option<&'a TypeField> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().ok()?.get_field(i); }
        if i < 0 {
            return None;
        }
        match &self.data.kind {
            DatatypeKind::Struct { field, .. } => field.get(i as usize),
            DatatypeKind::Union { field } => field.get(i as usize),
            _ => None,
        }
    }

    pub fn find_truncation(
        &self,
        off: int8,
        sz: int4,
        _op: crate::context::OpId,
        _slot: int4,
    ) -> KunaResult<Option<(int4, int8)>> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.find_truncation(off, sz, _op, _slot); }
        match &self.data.kind {
            DatatypeKind::Struct { field, .. } => {
                let i = self.get_field_iter(field, off as int4);
                if i < 0 {
                    return Ok(None);
                }
                let curfield = &field[i as usize];
                let noff = off - curfield.offset as int8;
                if noff + sz as int8 > self.node(curfield.field_type).get_size() as int8 {
                    return Ok(None);
                }
                Ok(Some((i, noff)))
            }
            DatatypeKind::Union { .. } => Err(KunaError::lowlevel(
                "TypeUnion::findTruncation must route through Funcdata::find_truncation",
            )),
            DatatypeKind::PartialUnion { .. } => Err(KunaError::lowlevel(
                "TypePartialUnion::findTruncation must route through Funcdata::find_truncation",
            )),
            _ => Ok(None),
        }
    }

    pub fn resolve_truncation(
        &self,
        _offset: int8,
        _op: crate::context::OpId,
        _slot: int4,
    ) -> KunaResult<Option<(int4, int8)>> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.resolve_truncation(_offset, _op, _slot); }
        match &self.data.kind {
            DatatypeKind::Union { .. } | DatatypeKind::PartialUnion { .. } => {
                Err(KunaError::lowlevel(
                    "Datatype::resolveTruncation must route through Funcdata::resolve_truncation",
                ))
            }
            _ => Ok(None),
        }
    }

    pub fn has_named_value(&self, val: u64) -> bool {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective().is_ok_and(|ty| ty.has_named_value(val)); }
        match &self.data.kind {
            DatatypeKind::Enum { namemap } => namemap.contains_key(&val),
            DatatypeKind::PartialEnum { parent, offset, .. } => {
                let shifted = val.wrapping_shl(8u32.wrapping_mul(*offset as u32));
                self.node(*parent).has_named_value(shifted)
            }
            _ => false,
        }
    }

    pub fn get_matches(&self, val: u64) -> KunaResult<EnumRepresentation> {
        if matches!(self.data.kind, DatatypeKind::Alias) { return self.effective()?.get_matches(val); }
        match &self.data.kind {
            DatatypeKind::Enum { namemap } => Ok(Self::enum_get_matches(namemap, self.size, val, 0)),
            DatatypeKind::PartialEnum { parent, offset, .. } => {
                let shifted = val.wrapping_shl(8u32.wrapping_mul(*offset as u32));
                let shift_amount = *offset * 8;
                let namemap = self.node(*parent).as_enum_namemap()
                    .ok_or_else(|| Self::enum_invariant_err("getMatches"))?;
                Ok(Self::enum_get_matches(namemap, self.node(*parent).size, shifted, shift_amount))
            }
            _ => Err(Self::enum_invariant_err("getMatches")),
        }
    }

    fn enum_get_matches(
        namemap: &std::collections::BTreeMap<u64, String>,
        size: int4,
        mut val: u64,
        shift_amount: int4,
    ) -> EnumRepresentation {
        let mut rep = EnumRepresentation { match_name: Vec::new(), complement: false, shift_amount };
        for count in 0..2 {
            let mut allmatch = true;
            if val == 0 {
                if let Some(nm) = namemap.get(&val) {
                    rep.match_name.push(nm.clone());
                } else {
                    allmatch = false;
                }
            } else {
                let mut bitsleft = val;
                let mut target = val;
                while target != 0 {
                    let next_greater = namemap
                        .range((std::ops::Bound::Excluded(target), std::ops::Bound::Unbounded))
                        .next();
                    let pred = match next_greater {
                        Some((k, _)) => {
                            namemap
                                .range((std::ops::Bound::Unbounded, std::ops::Bound::Excluded(*k)))
                                .next_back()
                        }
                        None => {
                            namemap.iter().next_back()
                        }
                    };
                    let (curval, curname) = match pred {
                        Some((k, v)) => (*k, v),
                        None => break,
                    };
                    let diff = kuna_base::address::coveringmask(bitsleft ^ curval);
                    if diff >= bitsleft {
                        break;
                    }
                    if (curval & diff) == 0 {
                        rep.match_name.push(curname.clone());
                        bitsleft ^= curval;
                        target = bitsleft;
                    } else {
                        target = curval & !diff;
                    }
                }
                allmatch = bitsleft == 0;
            }
            if allmatch {
                rep.complement = count == 1;
                return rep;
            }
            val ^= kuna_base::address::calc_mask(size);
            rep.match_name.clear();
        }
        rep
    }

    pub fn get_typedef(&self) -> Option<TypeId> { self.typedef_imm }

    pub fn get_code_prototype(&self) -> Option<&'a crate::fspec::LogicalCallable> {
        match &self.data.kind {
            DatatypeKind::Alias => self.effective().ok()?.get_code_prototype(),
            DatatypeKind::Code { proto } => proto.as_ref(),
            _ => None,
        }
    }

    fn encode_basic(
        &self,
        meta: type_metatype,
        align: int4,
        encoder: &mut dyn kuna_base::marshal::Encoder,
    ) -> KunaResult<()> {
        use kuna_base::marshal::{ATTRIB_ID, ATTRIB_METATYPE, ATTRIB_NAME, ATTRIB_SIZE};
        encoder.write_string(&ATTRIB_NAME, self.name.as_bytes());
        let save_id = self.get_unsized_id()?;
        if save_id != 0 {
            encoder.write_unsigned_integer(&ATTRIB_ID, save_id);
        }
        encoder.write_signed_integer(&ATTRIB_SIZE, self.size as i64);
        let metastring = metatype2string(meta)?;
        encoder.write_string(&ATTRIB_METATYPE, metastring.as_bytes());
        if align > 0 {
            encoder.write_signed_integer(&ATTRIB_ALIGNMENT, align as i64);
        }
        if (self.flags & flags::coretype) != 0 {
            encoder.write_bool(&ATTRIB_CORE, true);
        }
        if self.is_variable_length() {
            encoder.write_bool(&ATTRIB_VARLENGTH, true);
        }
        if (self.flags & flags::opaque_string) != 0 {
            encoder.write_bool(&ATTRIB_OPAQUESTRING, true);
        }
        let format = self.get_display_format();
        if format != 0 {
            encoder.write_string(
                &kuna_base::marshal::ATTRIB_FORMAT,
                Datatype::decode_integer_format(format)?.as_bytes(),
            );
        }
        Ok(())
    }

    fn encode_typedef(&self, encoder: &mut dyn kuna_base::marshal::Encoder) -> KunaResult<()> {
        use kuna_base::marshal::{ATTRIB_ID, ATTRIB_NAME};
        let imm = self
            .typedef_imm
            .as_ref()
            .ok_or_else(|| KunaError::lowlevel("Cannot encode an unresolved typedef"))?;
        encoder.open_element(&ELEM_DEF);
        encoder.write_string(&ATTRIB_NAME, self.name.as_bytes());
        encoder.write_unsigned_integer(&ATTRIB_ID, self.get_unsized_id()?);
        let format = self.get_display_format();
        if format != 0 {
            encoder.write_string(
                &kuna_base::marshal::ATTRIB_FORMAT,
                Datatype::decode_integer_format(format)?.as_bytes(),
            );
        }
        self.node(*imm).encode_ref(encoder)?;
        encoder.close_element(&ELEM_DEF);
        Ok(())
    }

    pub fn encode_ref(&self, encoder: &mut dyn kuna_base::marshal::Encoder) -> KunaResult<()> {
        use kuna_base::marshal::{ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE};
        if self.get_id() != 0 && self.metatype != type_metatype::TYPE_VOID {
            encoder.open_element(&ELEM_TYPEREF);
            encoder.write_string(&ATTRIB_NAME, self.name.as_bytes());
            if let Some(TypeInstance::Sized(size)) = self.get_instance() {
                encoder.write_unsigned_integer(&ATTRIB_ID, self.get_unsized_id()?);
                encoder.write_signed_integer(&ATTRIB_SIZE, size as i64);
            } else {
                encoder.write_unsigned_integer(&ATTRIB_ID, self.get_id());
            }
            encoder.close_element(&ELEM_TYPEREF);
            Ok(())
        } else {
            self.encode(encoder)
        }
    }

    pub fn encode(&self, encoder: &mut dyn kuna_base::marshal::Encoder) -> KunaResult<()> {
        use kuna_base::marshal::{
            ATTRIB_CONTENT, ATTRIB_NAME, ATTRIB_SPACE, ATTRIB_VALUE, ATTRIB_WORDSIZE, ELEM_OFF,
            ELEM_VAL, ELEM_VOID,
        };
        use kuna_base::marshal::ATTRIB_OFFSET;
        let elem_type = &crate::prettyprint::ids::ELEM_TYPE;
        if self.typedef_imm.is_some()
            && !matches!(
                self.kind,
                DatatypeKind::PartialStruct { .. }
                    | DatatypeKind::PartialUnion { .. }
                    | DatatypeKind::PartialEnum { .. }
                    | DatatypeKind::PointerRel { .. }
            )
        {
            return self.encode_typedef(encoder);
        }
        match &self.data.kind {
            DatatypeKind::Alias => return self.encode_typedef(encoder),
            DatatypeKind::Void => {
                encoder.open_element(&ELEM_VOID);
                encoder.close_element(&ELEM_VOID);
            }
            DatatypeKind::Base | DatatypeKind::Unknown => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, -1, encoder)?;
                if self.is_ascii() {
                    encoder.write_bool(&ATTRIB_CHAR, true);
                } else if self.is_utf16() || self.is_utf32() {
                    encoder.write_bool(&ATTRIB_UTF, true);
                }
                encoder.close_element(elem_type);
            }
            DatatypeKind::Enum { namemap } => {
                encoder.open_element(elem_type);
                let meta = if self.metatype == type_metatype::TYPE_INT {
                    type_metatype::TYPE_ENUM_INT
                } else {
                    type_metatype::TYPE_ENUM_UINT
                };
                self.encode_basic(meta, -1, encoder)?;
                for (val, nm) in namemap.iter() {
                    encoder.open_element(&ELEM_VAL);
                    encoder.write_string(&ATTRIB_NAME, nm.as_bytes());
                    encoder.write_unsigned_integer(&ATTRIB_VALUE, *val);
                    encoder.close_element(&ELEM_VAL);
                }
                encoder.close_element(elem_type);
            }
            DatatypeKind::Pointer { ptrto, spaceid, wordsize, .. } => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, -1, encoder)?;
                if *wordsize != 1 {
                    encoder.write_unsigned_integer(&ATTRIB_WORDSIZE, *wordsize as u64);
                }
                if let Some(spc) = spaceid {
                    encoder.write_space(&ATTRIB_SPACE, spc);
                }
                self.node(*ptrto).encode_ref(encoder)?;
                encoder.close_element(elem_type);
            }
            DatatypeKind::Array { arrayof, arraysize } => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, -1, encoder)?;
                encoder.write_signed_integer(&ATTRIB_ARRAYSIZE, *arraysize as i64);
                self.node(*arrayof).encode_ref(encoder)?;
                encoder.close_element(elem_type);
            }
            DatatypeKind::Struct { field, bitfield } => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, self.alignment, encoder)?;
                let mut i1 = field.iter().peekable();
                let mut i2 = bitfield.iter().peekable();
                while let (Some(f), Some(b)) = (i1.peek(), i2.peek()) {
                    if f.offset < b.byte_offset {
                        i1.next().unwrap().encode(self.graph, encoder)?;
                    } else {
                        i2.next().unwrap().encode(self.graph, encoder)?;
                    }
                }
                for f in i1 {
                    f.encode(self.graph, encoder)?;
                }
                for b in i2 {
                    b.encode(self.graph, encoder)?;
                }
                encoder.close_element(elem_type);
            }
            DatatypeKind::Union { field } => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, self.alignment, encoder)?;
                for f in field {
                    f.encode(self.graph, encoder)?;
                }
                encoder.close_element(elem_type);
            }
            DatatypeKind::Code { proto } => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, -1, encoder)?;
                if let Some(p) = proto {
                    p.encode(encoder, self)?;
                }
                encoder.close_element(elem_type);
            }
            DatatypeKind::Spacebase { spaceid, localframe } => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, -1, encoder)?;
                if let Some(spc) = spaceid {
                    encoder.write_space(&ATTRIB_SPACE, spc);
                }
                localframe.encode(encoder)?;
                encoder.close_element(elem_type);
            }
            DatatypeKind::PartialStruct { .. } => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, -1, encoder)?;
                encoder.close_element(elem_type);
            }
            DatatypeKind::PartialUnion { container, offset, .. } => {
                encoder.open_element(elem_type);
                self.encode_basic(self.metatype, -1, encoder)?;
                encoder.write_signed_integer(&ATTRIB_OFFSET, *offset as i64);
                self.node(*container).encode_ref(encoder)?;
                encoder.close_element(elem_type);
            }
            DatatypeKind::PartialEnum { parent, offset, .. } => {
                encoder.open_element(elem_type);
                self.encode_basic(type_metatype::TYPE_PARTIALENUM, -1, encoder)?;
                encoder.write_signed_integer(&ATTRIB_OFFSET, *offset as i64);
                self.node(*parent).encode_ref(encoder)?;
                encoder.close_element(elem_type);
            }
            DatatypeKind::PointerRel { ptrto, spaceid, wordsize, parent, offset, .. } => {
                encoder.open_element(elem_type);
                self.encode_basic(type_metatype::TYPE_PTRREL, -1, encoder)?;
                if *wordsize != 1 {
                    encoder.write_unsigned_integer(&ATTRIB_WORDSIZE, *wordsize as u64);
                }
                if let Some(spc) = spaceid {
                    encoder.write_space(&ATTRIB_SPACE, spc);
                }
                self.node(*ptrto).encode(encoder)?;
                self.node(*parent).encode_ref(encoder)?;
                encoder.open_element(&ELEM_OFF);
                encoder.write_signed_integer(&ATTRIB_CONTENT, *offset as i64);
                encoder.close_element(&ELEM_OFF);
                encoder.close_element(elem_type);
            }
        }
        Ok(())
    }
}

impl TypeRoot {
    pub fn is_core_type(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_core_type()
    }

    pub fn is_char_print(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_char_print()
    }

    pub fn is_enum_type(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_enum_type()
    }

    pub fn is_ascii(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_ascii()
    }

    pub fn is_utf16(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_utf16()
    }

    pub fn is_utf32(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_utf32()
    }

    pub fn is_variable_length(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_variable_length()
    }

    pub fn is_opaque_string(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_opaque_string()
    }

    pub fn is_pointer_to_array(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_pointer_to_array()
    }

    pub fn is_pointer_rel(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_pointer_rel()
    }

    pub fn is_formal_pointer_rel(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_formal_pointer_rel()
    }

    pub fn has_stripped(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").has_stripped()
    }

    pub fn is_incomplete(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_incomplete()
    }

    pub fn needs_resolution(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").needs_resolution()
    }

    pub fn has_warning(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").has_warning()
    }

    pub fn has_bitfields(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").has_bitfields()
    }

    pub fn inherit_for_pointer(&self) -> uint4 {
        self.read().get(self.id()).expect("root belongs to its graph").inherit_for_pointer()
    }

    pub fn inherit_for_partial(&self) -> uint4 {
        self.read().get(self.id()).expect("root belongs to its graph").inherit_for_partial()
    }

    pub fn get_display_format(&self) -> uint4 {
        self.read().get(self.id()).expect("root belongs to its graph").get_display_format()
    }

    pub fn get_metatype(&self) -> type_metatype {
        self.read().get(self.id()).expect("root belongs to its graph").get_metatype()
    }

    pub fn get_sub_meta(&self) -> sub_metatype {
        self.read().get(self.id()).expect("root belongs to its graph").get_sub_meta()
    }

    pub fn get_id(&self) -> uint8 {
        self.read().get(self.id()).expect("root belongs to its graph").get_id()
    }

    pub fn get_size(&self) -> int4 {
        self.read().get(self.id()).expect("root belongs to its graph").get_size()
    }

    pub fn get_align_size(&self) -> int4 {
        self.read().get(self.id()).expect("root belongs to its graph").get_align_size()
    }

    pub fn get_alignment(&self) -> int4 {
        self.read().get(self.id()).expect("root belongs to its graph").get_alignment()
    }

    pub fn get_unsized_id(&self) -> KunaResult<uint8> {
        self.read().get(self.id()).expect("root belongs to its graph").get_unsized_id()
    }

    pub fn is_piece_structured(&self) -> bool {
        self.read().get(self.id()).expect("root belongs to its graph").is_piece_structured()
    }

    pub fn type_order_formal(&self, op: &TypeRoot) -> KunaResult<int4> {
        let view = self.read();
        let this = view.get(self.id())?;
        let op_view = op.read();
        let op_ref = op_view.get(op.id())?;
        this.type_order_formal(&op_ref)
    }

    pub fn type_order(&self, op: &TypeRoot) -> KunaResult<int4> {
        let view = self.read();
        let this = view.get(self.id())?;
        let op_view = op.read();
        let op_ref = op_view.get(op.id())?;
        this.type_order(&op_ref)
    }

    pub fn has_same_variable_base(&self, ct: &TypeRoot) -> KunaResult<bool> {
        let view = self.read();
        let this = view.get(self.id())?;
        let ct_view = ct.read();
        let ct_ref = ct_view.get(ct.id())?;
        this.has_same_variable_base(&ct_ref)
    }

    pub fn num_depend(&self) -> int4 {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.num_depend()
    }

    pub fn get_depend(&self, index: int4) -> Option<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_depend(index).map(|id| this.graph.root(id).expect("validated datatype edge"))
    }

    pub fn get_ptr_into(&self) -> KunaResult<Option<(TypeRoot, int4)>> {
        let view = self.read();
        let this = view.get(self.id())?;
        match this.get_ptr_into()? { Some((id, off)) => Ok(Some((this.graph.root(id)?, off))), None => Ok(None) }
    }

    pub fn get_partial_base(&self) -> Option<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_partial_base().map(|id| this.graph.root(id).expect("validated datatype edge"))
    }

    pub fn get_stripped(&self) -> Option<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_stripped().map(|id| this.graph.root(id).expect("validated datatype edge"))
    }

    pub fn get_component_for_ptr(&self) -> Option<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_component_for_ptr().map(|id| this.graph.root(id).expect("validated datatype edge"))
    }

    pub fn get_ptr_to(&self) -> Option<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_ptr_to().map(|id| this.graph.root(id).expect("validated datatype edge"))
    }

    pub fn get_word_size(&self) -> Option<uint4> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_word_size()
    }

    pub fn spacebase_parts(&self) -> Option<(Option<Rc<AddrSpace>>, Address)> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.spacebase_parts()
    }

    pub fn get_pointer_space(&self) -> Option<Rc<AddrSpace>> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_pointer_space()
    }

    pub fn get_array_base(&self) -> Option<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_array_base().map(|id| this.graph.root(id).expect("validated datatype edge"))
    }

    pub fn num_elements(&self) -> Option<int4> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.num_elements()
    }

    pub fn get_rel_parent(&self) -> Option<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_rel_parent().map(|id| this.graph.root(id).expect("validated datatype edge"))
    }

    pub fn get_byte_offset(&self) -> Option<int4> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_byte_offset()
    }

    pub fn get_address_offset(&self) -> Option<int4> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_address_offset()
    }

    pub fn spacebase_get_address(&self, off: uint8, sz: int4, point: &Address, manager: &kuna_base::space::AddrSpaceManager) -> Option<Address> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.spacebase_get_address(off, sz, point, manager)
    }

    pub fn evaluate_thru_parent(&self, addr_off: u64) -> Option<bool> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.evaluate_thru_parent(addr_off)
    }

    pub fn get_partial_offset(&self) -> Option<int4> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_partial_offset()
    }

    pub fn compare(&self, op: &TypeRoot, level: int4) -> KunaResult<int4> {
        let view = self.read();
        let this = view.get(self.id())?;
        let op_view = op.read();
        let op_ref = op_view.get(op.id())?;
        this.compare(&op_ref, level)
    }

    pub fn compare_dependency(&self, op: &TypeRoot) -> KunaResult<int4> {
        let view = self.read();
        let this = view.get(self.id())?;
        let op_view = op.read();
        let op_ref = op_view.get(op.id())?;
        this.compare_dependency(&op_ref)
    }

    pub fn collect_bit_fields(&self, base_offset: int4, res: &mut Vec<BitFieldTriple>, offset: int4, sz: int4) {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.collect_bit_fields(base_offset, res, offset, sz)
    }

    pub fn has_bit_fields_in_range(&self, offset: int4, sz: int4) -> bool {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.has_bit_fields_in_range(offset, sz)
    }

    pub fn find_matching_bit_field(&self, range: &BitRange) -> Option<TypeBitField> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.find_matching_bit_field(range)
    }

    pub fn get_sub_type(&self, off: int8) -> KunaResult<(Option<TypeRoot>, int8)> {
        let view = self.read();
        let this = view.get(self.id())?;
        let (id, offset) = this.get_sub_type(off)?;
        Ok((id.map(|id| this.graph.root(id)).transpose()?, offset))
    }

    pub fn get_hole_size(&self, off: int4) -> KunaResult<int4> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.get_hole_size(off)
    }

    pub fn nearest_arrayed_component_forward(&self, off: int8, max: int8) -> KunaResult<(int8, int8, int8)> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.nearest_arrayed_component_forward(off, max)
    }

    pub fn nearest_arrayed_component_backward(&self, off: int8, max: int8) -> KunaResult<(int8, int8, int8)> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.nearest_arrayed_component_backward(off, max)
    }

    pub fn is_ptrsub_matching(&self, off: int8, extra: int8, multiplier: int8) -> KunaResult<bool> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.is_ptrsub_matching(off, extra, multiplier)
    }

    pub fn is_primitive_whole(&self) -> bool {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.is_primitive_whole()
    }

    pub fn resolve_in_flow(&self, _op: crate::context::OpId, _slot: int4) -> KunaResult<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.graph.root(this.resolve_in_flow(_op, _slot)?)
    }

    pub fn find_resolve(&self, _op: crate::context::OpId, _slot: int4) -> KunaResult<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.graph.root(this.find_resolve(_op, _slot)?)
    }

    pub fn find_compatible_resolve(&self, ct: &TypeRoot) -> KunaResult<int4> {
        let view = self.read();
        let this = view.get(self.id())?;
        let ct_view = ct.read();
        let ct_ref = ct_view.get(ct.id())?;
        this.find_compatible_resolve(&ct_ref)
    }

    pub fn find_truncation(&self, off: int8, sz: int4, _op: crate::context::OpId, _slot: int4) -> KunaResult<Option<(int4, int8)>> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.find_truncation(off, sz, _op, _slot)
    }

    pub fn resolve_truncation(&self, _offset: int8, _op: crate::context::OpId, _slot: int4) -> KunaResult<Option<(int4, int8)>> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.resolve_truncation(_offset, _op, _slot)
    }

    pub fn has_named_value(&self, val: u64) -> bool {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.has_named_value(val)
    }

    pub fn get_matches(&self, val: u64) -> KunaResult<EnumRepresentation> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.get_matches(val)
    }

    pub fn get_typedef(&self) -> Option<TypeRoot> {
        let view = self.read();
        let this = view.get(self.id()).expect("root belongs to its graph");
        this.get_typedef().map(|id| this.graph.root(id).expect("validated datatype edge"))
    }

    pub fn encode_ref(&self, encoder: &mut dyn kuna_base::marshal::Encoder) -> KunaResult<()> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.encode_ref(encoder)
    }

    pub fn encode(&self, encoder: &mut dyn kuna_base::marshal::Encoder) -> KunaResult<()> {
        let view = self.read();
        let this = view.get(self.id())?;
        this.encode(encoder)
    }

    pub(crate) fn test_for_array_slack(&self, off: int8) -> KunaResult<bool> {
        let view = self.read();
        TypeRef::test_for_array_slack(&view.get(self.id())?.effective()?, off)
    }
}

impl TypeField {
    pub(super) fn compare(&self, graph: GraphAccess<'_>, op2: &TypeField, other: GraphAccess<'_>) -> int4 {
        if self.offset != op2.offset {
            return if self.offset < op2.offset { -1 } else { 1 };
        }
        if self.name != op2.name {
            return if self.name < op2.name { -1 } else { 1 };
        }
        if graph.get(self.field_type).expect("validated field edge").get_metatype() != other.get(op2.field_type).expect("validated field edge").get_metatype() {
            return if graph.get(self.field_type).expect("validated field edge").get_metatype() < other.get(op2.field_type).expect("validated field edge").get_metatype() {
                -1
            } else {
                1
            };
        }
        0
    }

    pub(super) fn compare_dependency(&self, op2: &TypeField) -> int4 {
        if self.offset != op2.offset {
            return if self.offset < op2.offset { -1 } else { 1 };
        }
        if self.name != op2.name {
            return if self.name < op2.name { -1 } else { 1 };
        }
        TypeRef::compare_dependency_ptr(&self.field_type, &op2.field_type)
    }

    pub(super) fn encode(&self, graph: GraphAccess<'_>, encoder: &mut dyn kuna_base::marshal::Encoder) -> KunaResult<()> {
        use kuna_base::marshal::{ATTRIB_ID, ATTRIB_NAME, ATTRIB_OFFSET};
        let elem_field = &crate::prettyprint::ids::ELEM_FIELD;
        encoder.open_element(elem_field);
        encoder.write_string(&ATTRIB_NAME, self.name.as_bytes());
        encoder.write_signed_integer(&ATTRIB_OFFSET, self.offset as i64);
        if self.ident != self.offset {
            encoder.write_signed_integer(&ATTRIB_ID, self.ident as i64);
        }
        graph.get(self.field_type)?.encode_ref(encoder)?;
        encoder.close_element(elem_field);
        Ok(())
    }

    pub(super) fn compare_max_byte(&self, graph: GraphAccess<'_>, off: int4) -> bool {
        off < self.offset + graph.get(self.field_type).expect("validated field edge").get_size()
    }
}

impl TypeBitField {
    pub(super) fn compare(&self, graph: GraphAccess<'_>, op2: &TypeBitField, other: GraphAccess<'_>) -> int4 {
        let res = self.bits_compare(op2);
        if res != 0 {
            return res;
        }
        if self.name != op2.name {
            return if self.name < op2.name { -1 } else { 1 };
        }
        if graph.get(self.field_type).expect("validated field edge").get_metatype() != other.get(op2.field_type).expect("validated field edge").get_metatype() {
            return if graph.get(self.field_type).expect("validated field edge").get_metatype() < other.get(op2.field_type).expect("validated field edge").get_metatype() {
                -1
            } else {
                1
            };
        }
        0
    }

    pub(super) fn compare_dependency(&self, op2: &TypeBitField) -> int4 {
        let res = self.bits_compare(op2);
        if res != 0 {
            return res;
        }
        if self.name != op2.name {
            return if self.name < op2.name { -1 } else { 1 };
        }
        TypeRef::compare_dependency_ptr(&self.field_type, &op2.field_type)
    }

    pub(super) fn encode(&self, graph: GraphAccess<'_>, encoder: &mut dyn kuna_base::marshal::Encoder) -> KunaResult<()> {
        use kuna_base::marshal::{ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_SIZE};
        let elem_bitfield = &crate::prettyprint::ids::ELEM_BITFIELD;
        encoder.open_element(elem_bitfield);
        encoder.write_string(&ATTRIB_NAME, self.name.as_bytes());
        encoder.write_signed_integer(&ATTRIB_OFFSET, self.byte_offset as i64);
        encoder.write_signed_integer(&ATTRIB_SIZE, self.num_bits as i64);
        encoder
            .write_signed_integer(&kuna_base::address::ATTRIB_FIRST, self.least_sig_bit as i64);
        graph.get(self.field_type)?.encode_ref(encoder)?;
        encoder.close_element(elem_bitfield);
        Ok(())
    }
}

pub(super) fn assign_field_offsets(
    graph: GraphAccess<'_>,
        list: &mut [TypeField],
        bitlist: &mut [TypeBitField],
    ) -> KunaResult<(int4, int4, uint4)> {
        let mut next_bit_pos: int4 = -1;
        let mut cur_bit_ind: int4 = -1;
        if !bitlist.is_empty() {
            cur_bit_ind = 0;
            next_bit_pos = bitlist[0].ident;
        }
        let mut offset: int4 = 0;
        let mut new_align: int4 = 1;
        let mut flags: uint4 = 0;
        #[allow(clippy::needless_range_loop)]
        for pos in 0..list.len() {
            if pos as int4 == next_bit_pos {
                assign_contiguous_bitfields(
                    graph,
                    bitlist,
                    &mut cur_bit_ind,
                    &mut offset,
                    &mut new_align,
                )?;
                if (cur_bit_ind as usize) < bitlist.len() {
                    next_bit_pos = bitlist[cur_bit_ind as usize].ident;
                }
            }
            let cur_field = &mut list[pos];
            if graph.get(cur_field.field_type)?.get_metatype() == type_metatype::TYPE_VOID {
                return Err(KunaError::lowlevel("Illegal field data-type: void"));
            }
            if cur_field.offset != -1 {
                continue;
            }
            let cursize = graph.get(cur_field.field_type)?.get_align_size();
            let mut align = graph.get(cur_field.field_type)?.get_alignment();
            if align > new_align {
                new_align = align;
            }
            align -= 1;
            if align > 0 && (offset & align) != 0 {
                offset = offset - (offset & align) + (align + 1);
            }
            cur_field.offset = offset;
            cur_field.ident = offset;
            offset += cursize;
            if graph.get(cur_field.field_type)?.has_bitfields() {
                flags |= flags::has_bitfields;
            }
        }
        if list.len() as int4 == next_bit_pos {
            assign_contiguous_bitfields(
                    graph,
                bitlist,
                &mut cur_bit_ind,
                &mut offset,
                &mut new_align,
            )?;
        }
        if !bitlist.is_empty() && cur_bit_ind as usize != bitlist.len() {
            return Err(KunaError::lowlevel("Malformed bitfield description"));
        }
        if !bitlist.is_empty() {
            flags |= flags::has_bitfields;
        }
        let new_size = Datatype::calc_align_size(offset, new_align);
        Ok((new_size, new_align, flags))
    }

pub(super) fn assign_contiguous_bitfields(
    graph: GraphAccess<'_>,
        bitlist: &mut [TypeBitField],
        pos: &mut int4,
        offset: &mut int4,
        new_align: &mut int4,
    ) -> KunaResult<()> {
        let mut total_size: int4 = 0;
        let start_ind = *pos;
        let next_bit_pos = bitlist[*pos as usize].ident;
        while (*pos as usize) < bitlist.len() && bitlist[*pos as usize].ident == next_bit_pos {
            total_size += bitlist[*pos as usize].num_bits;
            *pos += 1;
        }
        let mut align = graph.get(bitlist[start_ind as usize].field_type)?.get_alignment();
        if align > *new_align {
            *new_align = align;
        }
        align -= 1;
        if align > 0 && (*offset & align) != 0 {
            *offset = *offset - (*offset & align) + (align + 1);
        }
        total_size = (total_size + 7) / 8;
        let mut lsb: int4 = 0;
        for i in start_ind..*pos {
            let bf = &mut bitlist[i as usize];
            bf.byte_offset = *offset;
            bf.byte_size = total_size;
            bf.least_sig_bit = lsb;
            lsb += bf.num_bits;
            bf.ident = i;
        }
        *offset += total_size;
        if bitlist[start_ind as usize].is_big_endian && (*pos - start_ind) > 1 {
            bitlist[start_ind as usize..*pos as usize].reverse();
        }
        Ok(())
}

pub(super) fn assign_union_field_offsets(
    graph: GraphAccess<'_>,
        list: &mut [TypeField],
        type_name: &str,
    ) -> KunaResult<(int4, int4)> {
        let mut new_size: int4 = 0;
        let mut new_align: int4 = 1;
        for f in list.iter_mut() {
            let ct = graph.get(f.field_type)?;
            if ct.get_metatype() == type_metatype::TYPE_VOID {
                return Err(KunaError::lowlevel(format!(
                    "Bad field data-type for union: {type_name}"
                )));
            }
            if f.name.is_empty() {
                return Err(KunaError::lowlevel(format!(
                    "Bad field name for union: {type_name}"
                )));
            }
            f.offset = 0;
            let end = ct.get_size();
            if end > new_size {
                new_size = end;
            }
            let cur_align = ct.get_alignment();
            if cur_align > new_align {
                new_align = cur_align;
            }
        }
        Ok((new_size, new_align))
    }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_metatype_discriminants() {
        use type_metatype::*;
        // These numbers are part of the type ordering and wire contracts.
        let ordered = [
            TYPE_PARTIALUNION, TYPE_PARTIALSTRUCT, TYPE_PARTIALENUM, TYPE_UNION,
            TYPE_STRUCT, TYPE_ENUM_INT, TYPE_ENUM_UINT, TYPE_ARRAY, TYPE_PTRREL,
            TYPE_PTR, TYPE_FLOAT, TYPE_CODE, TYPE_BOOL, TYPE_UINT, TYPE_INT,
            TYPE_UNKNOWN, TYPE_SPACEBASE, TYPE_VOID,
        ];
        for (value, meta) in ordered.into_iter().enumerate() {
            assert_eq!(meta as i32, value as i32);
        }
    }

    #[test]
    fn sub_metatype_discriminants() {
        use sub_metatype::*;
        let ordered = [
            SUB_PARTIALUNION, SUB_UNION, SUB_STRUCT, SUB_ARRAY, SUB_PTR_STRUCT,
            SUB_PTRREL, SUB_PTR, SUB_PTRREL_UNK, SUB_FLOAT, SUB_CODE, SUB_BOOL,
            SUB_UINT_UNICODE, SUB_INT_UNICODE, SUB_UINT_ENUM, SUB_UINT_PARTIALENUM,
            SUB_INT_ENUM, SUB_UINT_PLAIN, SUB_INT_PLAIN, SUB_UINT_CHAR, SUB_INT_CHAR,
            SUB_PARTIALSTRUCT, SUB_UNKNOWN, SUB_SPACEBASE, SUB_VOID,
        ];
        for (value, meta) in ordered.into_iter().enumerate() {
            assert_eq!(meta as i32, value as i32);
        }
    }

    #[test]
    fn type_class_discriminants() {
        use type_class::*;
        for (class, value) in [
            (TYPECLASS_GENERAL, 0), (TYPECLASS_FLOAT, 1), (TYPECLASS_PTR, 2),
            (TYPECLASS_HIDDENRET, 3), (TYPECLASS_VECTOR, 4), (TYPECLASS_CLASS1, 100),
            (TYPECLASS_CLASS2, 101), (TYPECLASS_CLASS3, 102), (TYPECLASS_CLASS4, 103),
        ] {
            assert_eq!(class as i32, value);
        }
    }

    #[test]
    fn base2sub_parity() {
        use sub_metatype::*;
        use type_metatype::*;
        for (meta, submeta) in [
            (TYPE_PARTIALUNION, SUB_PARTIALUNION),
            (TYPE_PARTIALSTRUCT, SUB_PARTIALSTRUCT),
            (TYPE_PARTIALENUM, SUB_UINT_PARTIALENUM),
            (TYPE_UNION, SUB_UNION), (TYPE_STRUCT, SUB_STRUCT),
            (TYPE_ENUM_INT, SUB_INT_ENUM), (TYPE_ENUM_UINT, SUB_UINT_ENUM),
            (TYPE_ARRAY, SUB_ARRAY), (TYPE_PTRREL, SUB_PTRREL), (TYPE_PTR, SUB_PTR),
            (TYPE_FLOAT, SUB_FLOAT), (TYPE_CODE, SUB_CODE), (TYPE_BOOL, SUB_BOOL),
            (TYPE_UINT, SUB_UINT_PLAIN), (TYPE_INT, SUB_INT_PLAIN),
            (TYPE_UNKNOWN, SUB_UNKNOWN), (TYPE_SPACEBASE, SUB_SPACEBASE),
            (TYPE_VOID, SUB_VOID),
        ] {
            assert_eq!(base2sub(meta), submeta);
        }
    }

    #[test]
    fn metatype_string_roundtrip() {
        use type_metatype::*;
        // Partial enums are not accepted by the upstream decoder vocabulary.
        for meta in [
            TYPE_PARTIALUNION, TYPE_PARTIALSTRUCT, TYPE_UNION, TYPE_STRUCT,
            TYPE_ENUM_INT, TYPE_ENUM_UINT, TYPE_ARRAY, TYPE_PTRREL, TYPE_PTR,
            TYPE_FLOAT, TYPE_CODE, TYPE_BOOL, TYPE_UINT, TYPE_INT, TYPE_UNKNOWN,
            TYPE_SPACEBASE, TYPE_VOID,
        ] {
            assert_eq!(string2metatype(&metatype2string(meta).unwrap()).unwrap(), meta);
        }
    }

    #[test]
    fn string2metatype_unknown_errors() {
        assert!(string2metatype("notatype").is_err());
        assert!(string2metatype("ptrx").is_err());
    }

    #[test]
    fn partenum_string_is_not_decodable() {
        let encoded = metatype2string(type_metatype::TYPE_PARTIALENUM).unwrap();
        assert!(string2metatype(&encoded).is_err());
    }

    #[test]
    fn string2typeclass_parity() {
        use type_class::*;
        for (name, class) in [
            ("general", TYPECLASS_GENERAL), ("float", TYPECLASS_FLOAT),
            ("ptr", TYPECLASS_PTR), ("pointer", TYPECLASS_PTR),
            ("hiddenret", TYPECLASS_HIDDENRET), ("vector", TYPECLASS_VECTOR),
            ("class1", TYPECLASS_CLASS1), ("class4", TYPECLASS_CLASS4),
            ("unknown", TYPECLASS_GENERAL),
        ] {
            assert_eq!(string2typeclass(name).unwrap(), class);
        }
        assert!(string2typeclass("bogus").is_err());
    }

    #[test]
    fn metatype2typeclass_parity() {
        use type_class::*;
        use type_metatype::*;
        assert_eq!(metatype2typeclass(TYPE_FLOAT), TYPECLASS_FLOAT);
        assert_eq!(metatype2typeclass(TYPE_PTR), TYPECLASS_PTR);
        assert_eq!(metatype2typeclass(TYPE_INT), TYPECLASS_GENERAL);
        assert_eq!(metatype2typeclass(TYPE_STRUCT), TYPECLASS_GENERAL);
    }

    fn scalar(factory: &TypeFactoryImpl, size: int4, meta: type_metatype) -> TypeRoot {
        factory.intern(Datatype::new_with_align(size, size.max(1), meta)).unwrap()
    }

    fn pointer_draft(
        ptrto: &TypeRoot,
        spaceid: Option<Rc<AddrSpace>>,
        wordsize: uint4,
    ) -> Datatype {
        let mut draft = Datatype::new_with_align(8, 8, type_metatype::TYPE_PTR);
        draft.kind = DatatypeKind::Pointer {
            ptrto: ptrto.id(),
            spaceid,
            truncate: None,
            wordsize,
        };
        draft
    }

    fn pointer(factory: &TypeFactoryImpl, ptrto: &TypeRoot) -> TypeRoot {
        factory.intern(pointer_draft(ptrto, None, 1)).unwrap()
    }

    fn array_draft(arrayof: &TypeRoot, arraysize: int4) -> Datatype {
        let mut draft = Datatype::new_with_align(
            arrayof.get_align_size() * arraysize,
            arrayof.get_alignment(),
            type_metatype::TYPE_ARRAY,
        );
        draft.kind = DatatypeKind::Array { arrayof: arrayof.id(), arraysize };
        draft
    }

    fn array(factory: &TypeFactoryImpl, arrayof: &TypeRoot, arraysize: int4) -> TypeRoot {
        factory.intern(array_draft(arrayof, arraysize)).unwrap()
    }

    fn structure(
        factory: &TypeFactoryImpl,
        size: int4,
        field: Vec<TypeField>,
        bitfield: Vec<TypeBitField>,
    ) -> TypeRoot {
        let mut draft = Datatype::new_with_align(size, 1, type_metatype::TYPE_STRUCT);
        draft.kind = DatatypeKind::Struct { field, bitfield };
        factory.intern(draft).unwrap()
    }

    fn relative_pointer(
        factory: &TypeFactoryImpl,
        ptrto: &TypeRoot,
        parent: &TypeRoot,
        stripped: Option<&TypeRoot>,
        offset: int4,
    ) -> TypeRoot {
        let mut draft = Datatype::new_with_align(8, 8, type_metatype::TYPE_PTR);
        draft.submeta = sub_metatype::SUB_PTRREL;
        draft.flags |= flags::is_ptrrel;
        if stripped.is_some() {
            draft.flags |= flags::has_stripped;
        }
        draft.kind = DatatypeKind::PointerRel {
            ptrto: ptrto.id(),
            spaceid: None,
            wordsize: 1,
            stripped: stripped.map(TypeRoot::id),
            parent: parent.id(),
            offset,
        };
        factory.intern(draft).unwrap()
    }

    fn space_with_index(index: int4) -> Rc<AddrSpace> {
        Rc::new(AddrSpace::new(
            kuna_base::space::spacetype::IPTR_PROCESSOR,
            "ram", false, 8, 1, index, 0, 0, 0,
        ))
    }

    #[test]
    fn compare_base_orders_submeta_then_size() {
        let factory = TypeFactoryImpl::new();
        let signed = scalar(&factory, 4, type_metatype::TYPE_INT);
        let unsigned = scalar(&factory, 4, type_metatype::TYPE_UINT);
        let wide = scalar(&factory, 8, type_metatype::TYPE_INT);
        assert_eq!(signed.compare(&unsigned, 10).unwrap(), 1);
        assert_eq!(unsigned.compare(&signed, 10).unwrap(), -1);
        assert_eq!(signed.compare(&wide, 10).unwrap(), 4);
        assert_eq!(signed.compare(&signed, 10).unwrap(), 0);
        assert_eq!(signed.compare_dependency(&unsigned).unwrap(), 1);
    }

    #[test]
    fn compare_struct_implemented() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 8, type_metatype::TYPE_INT);
        let empty = structure(&factory, 8, vec![], vec![]);
        let populated = structure(
            &factory, 8, vec![TypeField::new(0, 0, "a", integer.id())], vec![],
        );
        assert_eq!(empty.compare(&empty, 10).unwrap(), 0);
        assert_eq!(populated.compare(&empty, 10).unwrap(), -1);
        assert_eq!(empty.compare(&populated, 10).unwrap(), 1);
    }

    #[test]
    fn is_piece_structured_boundary() {
        for meta in [type_metatype::TYPE_ARRAY, type_metatype::TYPE_STRUCT] {
            assert!(Datatype::new(4, meta).is_piece_structured());
        }
        for meta in [type_metatype::TYPE_PTR, type_metatype::TYPE_INT] {
            assert!(!Datatype::new(4, meta).is_piece_structured());
        }
    }

    #[test]
    fn is_ptrsub_matching_routing() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        assert!(!integer.is_ptrsub_matching(0, 0, 1).unwrap());
        assert!(!pointer(&factory, &integer).is_ptrsub_matching(0, 0, 1).unwrap());
        let arr = array(&factory, &integer, 2);
        assert!(pointer(&factory, &arr).is_ptrsub_matching(0, 0, 1).unwrap());
        let record = structure(
            &factory, 8, vec![TypeField::new(0, 0, "a", integer.id())], vec![],
        );
        let ptr = pointer(&factory, &record);
        assert!(!ptr.is_ptrsub_matching(0, 4, 1).unwrap());
        assert!(ptr.is_ptrsub_matching(0, 0, 1).unwrap());
    }

    #[test]
    fn is_primitive_whole_recursion() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        assert!(integer.is_primitive_whole());
        assert!(array(&factory, &integer, 1).is_primitive_whole());
        let padded = structure(
            &factory, 8, vec![TypeField::new(0, 0, "a", integer.id())], vec![],
        );
        assert!(!padded.is_primitive_whole());
    }

    #[test]
    fn pointer_compare_tiebreaks() {
        let factory = TypeFactoryImpl::new();
        let int4 = scalar(&factory, 4, type_metatype::TYPE_INT);
        let int8 = scalar(&factory, 8, type_metatype::TYPE_INT);
        let plain = pointer(&factory, &int4);
        let ws2 = factory.intern(pointer_draft(&int4, None, 2)).unwrap();
        assert_eq!(plain.compare(&ws2, 10).unwrap(), -1);
        assert_eq!(ws2.compare(&plain, 10).unwrap(), 1);
        let space3 = factory.intern(pointer_draft(&int4, Some(space_with_index(3)), 1)).unwrap();
        let space5 = factory.intern(pointer_draft(&int4, Some(space_with_index(5)), 1)).unwrap();
        assert_eq!(plain.compare(&space3, 10).unwrap(), 1);
        assert_eq!(space3.compare(&plain, 10).unwrap(), -1);
        assert_eq!(space3.compare(&space5, 10).unwrap(), -1);
        assert_eq!(space5.compare(&space3, 10).unwrap(), 1);
        assert_eq!(plain.compare(&pointer(&factory, &int8), 10).unwrap(), 4);
        let mut a = pointer_draft(&int4, None, 1);
        a.id = 100;
        a.name = "depth_a".into();
        let mut b = pointer_draft(&int8, None, 1);
        b.id = 200;
        b.name = "depth_b".into();
        let a = factory.intern(a).unwrap();
        let b = factory.intern(b).unwrap();
        assert_eq!(a.compare(&b, 0).unwrap(), -1);
        assert_eq!(b.compare(&a, 0).unwrap(), 1);
    }

    #[test]
    fn pointer_compare_dependency_uses_nominal_identity() {
        let factory = TypeFactoryImpl::new();
        let a = factory.get_base_named(4, type_metatype::TYPE_INT, "integer_a").unwrap();
        let b = factory.get_base_named(4, type_metatype::TYPE_INT, "integer_b").unwrap();
        let pa = pointer(&factory, &a);
        let pa2 = pointer(&factory, &a);
        let pb = pointer(&factory, &b);
        assert_eq!(pa.compare_dependency(&pa2).unwrap(), 0);
        let ab = pa.compare_dependency(&pb).unwrap();
        assert_ne!(ab, 0);
        assert_eq!(ab, -pb.compare_dependency(&pa).unwrap());
    }

    #[test]
    fn array_compare_and_dependency() {
        let factory = TypeFactoryImpl::new();
        let int4 = scalar(&factory, 4, type_metatype::TYPE_INT);
        let int8 = scalar(&factory, 8, type_metatype::TYPE_INT);
        let narrow = array(&factory, &int4, 2);
        let wide = array(&factory, &int8, 1);
        assert_eq!(narrow.compare(&wide, 10).unwrap(), 4);
        assert_eq!(wide.compare(&narrow, 10).unwrap(), -4);
        assert_eq!(narrow.compare_dependency(&array(&factory, &int4, 2)).unwrap(), 0);
        let mut a = array_draft(&int4, 2);
        a.id = 7;
        a.name = "depth_array_a".into();
        let mut b = array_draft(&int8, 1);
        b.id = 9;
        b.name = "depth_array_b".into();
        let a = factory.intern(a).unwrap();
        let b = factory.intern(b).unwrap();
        assert_eq!(a.compare(&b, 0).unwrap(), -1);
    }

    #[test]
    fn compare_total_order_matrix() {
        let factory = TypeFactoryImpl::new();
        let i1 = scalar(&factory, 1, type_metatype::TYPE_INT);
        let i4 = scalar(&factory, 4, type_metatype::TYPE_INT);
        let f8 = scalar(&factory, 8, type_metatype::TYPE_FLOAT);
        let corpus = vec![
            i1.clone(), i4.clone(), f8.clone(),
            scalar(&factory, 4, type_metatype::TYPE_UINT),
            scalar(&factory, 1, type_metatype::TYPE_BOOL),
            pointer(&factory, &i4),
            factory.intern(pointer_draft(&i4, None, 2)).unwrap(),
            factory.intern(pointer_draft(&i4, Some(space_with_index(2)), 1)).unwrap(),
            pointer(&factory, &f8),
            array(&factory, &i4, 2),
            array(&factory, &i1, 4),
        ];
        for a in &corpus {
            assert_eq!(a.compare(a, 10).unwrap(), 0);
            assert_eq!(a.compare_dependency(a).unwrap(), 0);
            for b in &corpus {
                let ab = a.compare(b, 10).unwrap().signum();
                assert_eq!(ab, -b.compare(a, 10).unwrap().signum());
                assert_eq!(
                    a.compare_dependency(b).unwrap().signum(),
                    -b.compare_dependency(a).unwrap().signum(),
                );
                for c in &corpus {
                    let bc = b.compare(c, 10).unwrap().signum();
                    let ac = a.compare(c, 10).unwrap().signum();
                    if ab < 0 && bc < 0 {
                        assert!(ac < 0);
                    }
                    if ab == 0 && bc == 0 {
                        assert_eq!(ac, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn get_sub_type_pointer_and_array() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        let arr = array(&factory, &integer, 3);
        assert_eq!(arr.get_sub_type(7).unwrap(), (Some(integer.clone()), 3));
        assert_eq!(arr.get_sub_type(12).unwrap(), (None, 12));
        let mut ptr = pointer_draft(&integer, None, 1);
        ptr.size = 16;
        ptr.align_size = 16;
        ptr.alignment = 16;
        let ptr = factory.intern(ptr).unwrap();
        assert_eq!(ptr.get_sub_type(3).unwrap(), (None, 3));
        let mut truncated = pointer_draft(&integer, None, 1);
        truncated.size = 4;
        truncated.align_size = 4;
        truncated.alignment = 4;
        let truncated = factory.intern(truncated).unwrap();
        let mut wide = pointer_draft(&integer, None, 1);
        if let DatatypeKind::Pointer { truncate, .. } = &mut wide.kind {
            *truncate = Some(truncated.id());
        }
        let wide = factory.intern(wide).unwrap();
        assert_eq!(wide.get_sub_type(2).unwrap(), (Some(truncated), 2));
        assert_eq!(wide.get_sub_type(5).unwrap(), (None, 5));
    }

    #[test]
    fn nearest_arrayed_component() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        let arr = array(&factory, &integer, 3);
        assert_eq!(arr.nearest_arrayed_component_forward(0, 128).unwrap(), (0, 0, 4));
        assert_eq!(arr.nearest_arrayed_component_forward(4, 128).unwrap().0, -1);
        assert_eq!(arr.nearest_arrayed_component_backward(4, 128).unwrap(), (8, 4, 4));
        assert_eq!(arr.nearest_arrayed_component_backward(-1, 128).unwrap().0, -1);
        assert_eq!(integer.nearest_arrayed_component_forward(0, 128).unwrap().0, -1);
        assert_eq!(integer.nearest_arrayed_component_backward(0, 128).unwrap().0, -1);
    }

    #[test]
    fn array_get_hole_size() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        let arr = array(&factory, &integer, 3);
        assert_eq!(arr.get_hole_size(5).unwrap(), 0);
    }

    #[test]
    fn resolve_in_flow_preserves_identity_and_requires_union_context() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        let op = crate::context::OpId::default();
        assert_eq!(integer.resolve_in_flow(op, 0).unwrap(), integer);
        assert_eq!(integer.find_resolve(op, -1).unwrap(), integer);
        let ptr = pointer(&factory, &integer);
        assert_eq!(ptr.resolve_in_flow(op, 0).unwrap(), ptr);
        assert!(array(&factory, &integer, 2).resolve_in_flow(op, 0).is_err());
        let mut union = Datatype::new_with_align(8, 8, type_metatype::TYPE_UNION);
        union.kind = DatatypeKind::Union { field: vec![] };
        let union = factory.intern(union).unwrap();
        assert!(pointer(&factory, &union).resolve_in_flow(op, 0).is_err());
    }

    #[test]
    fn pointer_rel_compare_prefers_formal() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        let parent = structure(&factory, 16, vec![], vec![]);
        let stripped = pointer(&factory, &integer);
        let formal = relative_pointer(&factory, &integer, &parent, None, 4);
        let ephemeral = relative_pointer(&factory, &integer, &parent, Some(&stripped), 4);
        assert_eq!(formal.compare(&ephemeral, 10).unwrap(), -1);
        assert_eq!(ephemeral.compare(&formal, 10).unwrap(), 1);
        let formal2 = relative_pointer(&factory, &integer, &parent, None, 4);
        assert_eq!(formal.compare(&formal2, 10).unwrap(), 0);
    }

    #[test]
    fn pointer_rel_compare_dependency_fields() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        let parent = structure(&factory, 16, vec![], vec![]);
        let a = relative_pointer(&factory, &integer, &parent, None, 4);
        let a2 = relative_pointer(&factory, &integer, &parent, None, 4);
        let b = relative_pointer(&factory, &integer, &parent, None, 8);
        assert_eq!(a.compare_dependency(&a2).unwrap(), 0);
        assert_eq!(a.compare_dependency(&b).unwrap(), -1);
        assert_eq!(b.compare_dependency(&a).unwrap(), 1);
    }

    #[test]
    fn pointer_rel_is_ptrsub_matching_bounds() {
        let factory = TypeFactoryImpl::new();
        let integer = scalar(&factory, 4, type_metatype::TYPE_INT);
        let parent = structure(&factory, 16, vec![], vec![]);
        let ptr = relative_pointer(&factory, &integer, &parent, None, 4);
        assert!(ptr.is_ptrsub_matching(0, 0, 1).unwrap());
        assert!(ptr.is_ptrsub_matching(0, 12, 1).unwrap());
        assert!(!ptr.is_ptrsub_matching(0, 13, 1).unwrap());
        assert!(!ptr.is_ptrsub_matching(-5, 0, 1).unwrap());
    }

    fn myfoo_byte0_bitfields(factory: &TypeFactoryImpl) -> Vec<TypeBitField> {
        let make = |id, lsb, count, name: &str, meta| {
            let ty = scalar(factory, 4, meta);
            let mut field = TypeBitField::new(id, count, false, name, ty.id());
            field.least_sig_bit = lsb;
            field.byte_offset = 0;
            field.byte_size = 1;
            field
        };
        vec![
            make(0, 0, 3, "field3", type_metatype::TYPE_UINT),
            make(1, 3, 4, "sfield4", type_metatype::TYPE_INT),
            make(2, 7, 1, "fieldb", type_metatype::TYPE_BOOL),
        ]
    }

    #[test]
    fn collect_bit_fields_single_byte_container() {
        let factory = TypeFactoryImpl::new();
        let record = structure(&factory, 1, vec![], myfoo_byte0_bitfields(&factory));
        let mut fields = Vec::new();
        record.collect_bit_fields(0, &mut fields, 0, 1);
        let actual: Vec<_> = fields.iter().map(|f| (f.bitfield.name.as_str(), f.offset)).collect();
        assert_eq!(actual, vec![("field3", 0), ("sfield4", 0), ("fieldb", 0)]);
    }

    #[test]
    fn collect_bit_fields_range_outside_container_is_empty() {
        let factory = TypeFactoryImpl::new();
        let record = structure(&factory, 4, vec![], myfoo_byte0_bitfields(&factory));
        let mut fields = Vec::new();
        record.collect_bit_fields(0, &mut fields, 2, 1);
        assert!(fields.is_empty());
    }

    #[test]
    fn has_bit_fields_in_range_matches_collect() {
        let factory = TypeFactoryImpl::new();
        let record = structure(&factory, 4, vec![], myfoo_byte0_bitfields(&factory));
        assert!(record.has_bit_fields_in_range(0, 1));
        assert!(!record.has_bit_fields_in_range(2, 2));
        assert!(!scalar(&factory, 4, type_metatype::TYPE_INT).has_bit_fields_in_range(0, 4));
    }

    #[test]
    fn collect_bit_fields_nested_struct_recurses() {
        let factory = TypeFactoryImpl::new();
        let inner = structure(&factory, 1, vec![], myfoo_byte0_bitfields(&factory));
        let outer = structure(
            &factory, 8, vec![TypeField::new(0, 4, "inner", inner.id())], vec![],
        );
        let mut fields = Vec::new();
        outer.collect_bit_fields(0, &mut fields, 0, 8);
        let actual: Vec<_> = fields.iter().map(|f| (f.bitfield.name.as_str(), f.offset)).collect();
        assert_eq!(actual, vec![("field3", 4), ("sfield4", 4), ("fieldb", 4)]);
    }

    #[test]
    fn bitfield_triple_compare_orders_least_to_most_significant() {
        let factory = TypeFactoryImpl::new();
        let fields = myfoo_byte0_bitfields(&factory);
        let low = BitFieldTriple::new(fields[0].clone(), 0);
        let middle = BitFieldTriple::new(fields[1].clone(), 0);
        assert!(BitFieldTriple::compare(&low, &middle));
        assert!(!BitFieldTriple::compare(&middle, &low));
        assert!(!BitFieldTriple::compare(&low, &low));
        let mut high = fields[0].clone();
        high.byte_offset = 2;
        let high = BitFieldTriple::new(high, 0);
        assert!(BitFieldTriple::compare(&low, &high));
        assert!(!BitFieldTriple::compare(&high, &low));
    }
}
