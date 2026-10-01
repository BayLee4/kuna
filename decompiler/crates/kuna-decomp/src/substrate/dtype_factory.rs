use super::*;

pub trait TypeFactory {
    fn root(&self, id: TypeId) -> KunaResult<TypeRoot>;
    fn find_by_source_id(&self, name: &str, host_id: u64) -> KunaResult<Option<TypeRoot>>;
    fn find_by_instance(&self, name: &str, host_id: u64, size: Option<int4>) -> Option<TypeRoot>;
    fn intern(&self, draft: Datatype) -> KunaResult<TypeRoot>;
    fn reserve(&self, name: &str, host_id: u64, meta: type_metatype) -> KunaResult<TypeRoot>;
    fn reserve_alias(&self, name: &str, host_id: u64) -> KunaResult<TypeRoot>;
    fn reserve_inferred(&self, name: &str, host_id: u64, meta: type_metatype) -> KunaResult<TypeRoot>;
    fn retire_inferred(&self, roots: &[TypeRoot]) -> KunaResult<Vec<TypeId>>;
    fn begin(&self, root: &TypeRoot) -> KunaResult<()>;
    fn complete(&self, root: &TypeRoot, draft: Datatype) -> KunaResult<()>;
    fn correct_pending(&self, root: &TypeRoot, draft: Datatype) -> KunaResult<()>;
    fn fail(&self, root: &TypeRoot, reason: String) -> KunaResult<()>;
    fn state(&self, root: &TypeRoot) -> KunaResult<TypeState>;
    fn decode_type(&self, decoder: &mut dyn Decoder) -> KunaResult<TypeRoot>;
    fn model_context_id(&self) -> Option<crate::fspec::ModelContextId>;
    fn model_binding(&self, name: Option<&str>) -> KunaResult<crate::fspec::ModelBinding>;
    fn model_binding_for(&self, model: Rc<crate::fspec::ProtoModel>) -> KunaResult<crate::fspec::ModelBinding>;
    fn get_abi_view(&self, id: TypeId) -> Option<Rc<crate::fspec::AbiView>>;
    fn cache_abi_view(&self, id: TypeId, view: Rc<crate::fspec::AbiView>) -> KunaResult<()>;
    fn kuna_variant_types(&self) -> Vec<TypeRoot>;

    // -- Size queries (type.hh:880-885) -------------------------------------

    fn get_size_of_int(&self) -> int4;
    fn get_size_of_long(&self) -> int4;
    fn get_size_of_char(&self) -> int4;
    fn get_size_of_wchar(&self) -> int4;
    fn get_size_of_pointer(&self) -> int4;
    fn get_size_of_alt_pointer(&self) -> int4;
    fn get_size_of_short(&self) -> int4 {
        2
    }
    fn get_size_of_long_long(&self) -> int4 {
        8
    }
    fn get_size_of_float(&self) -> int4 {
        4
    }
    fn get_size_of_double(&self) -> int4 {
        8
    }
    fn get_size_of_long_double(&self) -> int4 {
        8
    }
    fn get_alignment(&self, size: uint4) -> KunaResult<int4>;
    fn get_primitive_align_size(&self, size: uint4) -> KunaResult<int4>;

    // -- Atomic / core getters (type.hh:894-899) ----------------------------

    fn get_type_void(&self) -> KunaResult<TypeRoot>;
    fn get_base_no_char(&self, s: int4, m: type_metatype) -> KunaResult<TypeRoot>;
    fn get_base(&self, s: int4, m: type_metatype) -> KunaResult<TypeRoot>;
    fn get_base_named(&self, s: int4, m: type_metatype, n: &str) -> KunaResult<TypeRoot>;
    fn get_type_char(&self, s: int4) -> KunaResult<TypeRoot>;
    fn get_type_code(&self) -> KunaResult<TypeRoot>;
    fn get_type_code_proto(
        &self,
        _proto: &crate::fspec::LogicalCallable,
    ) -> KunaResult<TypeRoot>;

    // -- Pointer construction (type.hh:900-902,913-916) ---------------------

    fn get_type_pointer_strip_array(
        &self,
        s: int4,
        pt: TypeRoot,
        ws: uint4,
    ) -> KunaResult<TypeRoot>;
    fn get_type_pointer(&self, s: int4, pt: TypeRoot, ws: uint4) -> KunaResult<TypeRoot>;
    fn get_type_pointer_named(
        &self,
        s: int4,
        pt: TypeRoot,
        ws: uint4,
        n: &str,
    ) -> KunaResult<TypeRoot>;
    fn resize_pointer(&self, ptr: TypeRoot, new_size: int4) -> KunaResult<TypeRoot>;
    fn get_type_pointer_rel(
        &self,
        parent_ptr: TypeRoot,
        ptr_to: TypeRoot,
        off: int4,
    ) -> KunaResult<TypeRoot>;
    #[allow(clippy::too_many_arguments)]
    fn get_type_pointer_rel_full(
        &self,
        sz: int4,
        parent: TypeRoot,
        ptr_to: TypeRoot,
        ws: int4,
        off: int4,
        nm: &str,
    ) -> KunaResult<TypeRoot>;
    fn get_type_pointer_with_space(
        &self,
        size: int4,
        ptr_to: TypeRoot,
        wordsize: uint4,
        spc: Rc<AddrSpace>,
        nm: &str,
    ) -> KunaResult<TypeRoot>;

    fn get_ptr_to_from_parent(
        &self,
        base: TypeRoot,
        off: int4,
    ) -> KunaResult<TypeRoot> {
        if off > 0 {
            let mut curoff: int8 = off as int8;
            let mut base = base;
            loop {
                let (next, newoff) = base.get_sub_type(curoff)?;
                curoff = newoff;
                match next {
                    None => {
                        // base became null: getBase(1, TYPE_UNKNOWN).
                        return self.get_base(1, type_metatype::TYPE_UNKNOWN);
                    }
                    Some(next_ct) => {
                        base = next_ct;
                        if curoff == 0 {
                            break;
                        }
                    }
                }
            }
            Ok(base)
        } else {
            self.get_base(1, type_metatype::TYPE_UNKNOWN)
        }
    }

    // -- Composite construction (type.hh:903-912) ---------------------------

    fn get_type_array(&self, as_: int4, ao: TypeRoot) -> KunaResult<TypeRoot>;
    fn get_type_struct(&self, n: &str) -> KunaResult<TypeRoot>;
    fn get_type_partial_struct(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot>;
    fn get_type_union(&self, n: &str) -> KunaResult<TypeRoot>;
    fn get_type_partial_union(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot>;
    fn get_type_partial_enum(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot>;
    fn get_type_enum(&self, n: &str) -> KunaResult<TypeRoot>;
    fn get_type_enum_sized(
        &self,
        _n: &str,
        _s: int4,
        _m: type_metatype,
    ) -> KunaResult<TypeRoot>;
    fn get_type_spacebase(&self, id: Rc<AddrSpace>, addr: &Address) -> KunaResult<TypeRoot>;

    // -- Resizing / piece extraction (type.hh:917-918) ----------------------

    fn resize_integer(&self, ct: TypeRoot, new_size: int4) -> KunaResult<TypeRoot>;
    fn get_exact_piece(
        &self,
        ct: TypeRoot,
        offset: int4,
        size: int4,
    ) -> KunaResult<Option<TypeRoot>>;

    // -- Lookup / conversion (type.hh:887,922) ------------------------------

    fn find_by_name(&self, n: &str) -> KunaResult<Option<TypeRoot>>;
    fn concretize(&self, ct: TypeRoot) -> KunaResult<TypeRoot>;

    fn is_big_endian(&self) -> bool {
        false
    }
    fn set_name(&self, _ct: &TypeRoot, _n: &str) -> KunaResult<TypeRoot>;
    fn set_display_format(&self, _ct: &TypeRoot, _format: uint4) -> KunaResult<TypeRoot>;
    fn assign_raw_fields_struct(
        &self,
        _ct: &TypeRoot,
        _fd: Vec<TypeField>,
        _bit: Vec<TypeBitField>,
    ) -> KunaResult<TypeRoot>;
    fn assign_raw_fields_union(
        &self,
        _ct: &TypeRoot,
        _fd: Vec<TypeField>,
    ) -> KunaResult<TypeRoot>;
    /// Publish explicit structure geometry. `type_incomplete` in `extra_flags`
    /// retains a sized provisional definition: its width is observable, but it
    /// is not by-value layout-ready. A later call without that flag can complete
    /// the same identity once its fields and dependencies have valid layouts.
    fn set_fields_struct_raw(
        &self,
        _ct: &TypeRoot,
        _fd: Vec<TypeField>,
        _bit: Vec<TypeBitField>,
        _size: int4,
        _align: int4,
        _extra_flags: uint4,
    ) -> KunaResult<TypeRoot>;
    fn set_fields_union_raw(
        &self,
        _ct: &TypeRoot,
        _fd: Vec<TypeField>,
        _size: int4,
        _align: int4,
    ) -> KunaResult<TypeRoot>;
    fn set_enum_values(
        &self,
        _ct: &TypeRoot,
        _nmap: std::collections::BTreeMap<u64, String>,
    ) -> KunaResult<TypeRoot>;
    fn get_typedef(
        &self,
        _ct: &TypeRoot,
        _name: &str,
        _id: uint8,
        _format: uint4,
    ) -> KunaResult<TypeRoot>;
    fn destroy_type(&self, _ct: &TypeRoot) -> KunaResult<()>;

    fn kuna_record_variant_layout(&self, owner: &TypeRoot, layout: crate::kuna_dwarfvariants::VariantLayout) -> KunaResult<()>;




}

pub trait RemoteTypeFetch {
    fn fetch_data_type(
        &self,
        name: &str,
        id: u64,
        decoder: &mut dyn Decoder,
    ) -> KunaResult<bool>;
}

struct HostDecodeGuard<'a> {
    enabled: &'a Cell<bool>, previous: bool,
    pending: &'a RefCell<Vec<(TypeId, HostTypeSource, u64)>>, length: usize,
    keep_pending: bool,
}
impl Drop for HostDecodeGuard<'_> {
    fn drop(&mut self) {
        self.enabled.set(self.previous);
        if !self.keep_pending { self.pending.borrow_mut().truncate(self.length); }
    }
}
struct HostDefinitionGuard<'a> { definitions: &'a RefCell<Vec<HostTypeSource>>, length: usize }
impl Drop for HostDefinitionGuard<'_> {
    fn drop(&mut self) { self.definitions.borrow_mut().truncate(self.length); }
}

struct WireTypeAttribs {
    name: String,
    display: String,
    id: uint8,
    size: int4,
    metatype: Option<type_metatype>,
    core: bool,
    varlength: bool,
    alignment: int4,
    opaquestring: bool,
    char_flag: bool,
    utf_flag: bool,
    arraysize: int4,
    wordsize: u64,
    spaceid: Option<Rc<AddrSpace>>,
}

struct AliasHeader {
    name: String,
    id: uint8,
    format: uint4,
    constraint: Option<TypeInstance>,
    core: bool,
    root: Option<TypeRoot>,
    loading: bool,
}

impl Default for WireTypeAttribs {
    fn default() -> Self {
        WireTypeAttribs {
            name: String::new(),
            display: String::new(),
            id: 0,
            size: -1,
            metatype: None,
            core: false,
            varlength: false,
            alignment: -1,
            opaquestring: false,
            char_flag: false,
            utf_flag: false,
            arraysize: 0,
            wordsize: 0,
            spaceid: None,
        }
    }
}

impl WireTypeAttribs {
    fn extra_flags(&self, forcecore: bool) -> uint4 {
        let mut f: uint4 = 0;
        if self.core || forcecore {
            f |= flags::coretype;
        }
        if self.varlength {
            f |= flags::variable_length;
        }
        if self.opaquestring {
            f |= flags::opaque_string;
        }
        f
    }

    fn apply_names(&self, dt: &mut Datatype) {
        dt.name = self.name.clone();
        dt.display_name = if self.display.is_empty() {
            self.name.clone()
        } else {
            self.display.clone()
        };
        dt.id = self.id;
    }
}

fn wire_integer_format(s: &str) -> uint4 {
    match s {
        "hex" => 1,
        "dec" => 2,
        "oct" => 3,
        "bin" => 4,
        "char" => 5,
        _ => 0,
    }
}

struct FactoryStore {
    typecache: [[Option<TypeRoot>; 8]; 9],
    typecache10: Option<TypeRoot>,
    typecache16: Option<TypeRoot>,
    type_nochar: Option<TypeRoot>,
    charcache: [Option<TypeRoot>; 5],
}
impl FactoryStore {
    fn new() -> Self {
        Self {
            typecache: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            typecache10: None, typecache16: None, type_nochar: None,
            charcache: std::array::from_fn(|_| None),
        }
    }
}

pub struct TypeFactoryImpl {
    size_of_int: Cell<int4>,
    size_of_long: Cell<int4>,
    size_of_char: Cell<int4>,
    size_of_wchar: Cell<int4>,
    size_of_pointer: Cell<int4>,
    size_of_short: Cell<int4>,
    size_of_long_long: Cell<int4>,
    size_of_float: Cell<int4>,
    size_of_double: Cell<int4>,
    size_of_long_double: Cell<int4>,
    size_of_alt_pointer: Cell<int4>,
    enumsize: Cell<int4>,
    enumtype: Cell<type_metatype>,
    align_map: RefCell<Vec<int4>>,
    max_basetype_size: Cell<int4>,
    truncate_big_endian: Cell<bool>,
    store: RefCell<FactoryStore>,
    model_context: RefCell<Option<Rc<crate::fspec::ModelContext>>>,
    manager: RefCell<Option<Rc<kuna_base::space::AddrSpaceManager>>>,
    remote_types: RefCell<Option<Rc<dyn RemoteTypeFetch>>>,
    graph: GraphStore,
    abi_cache: RefCell<BTreeMap<TypeId, Rc<crate::fspec::AbiView>>>,
    building_core: Cell<bool>,
    host_decode: Cell<bool>,
    host_program: Cell<Option<u64>>,
    host_definitions: RefCell<Vec<HostTypeSource>>,
    pending_host_sources: RefCell<Vec<(TypeId, HostTypeSource, u64)>>,
}

impl Default for TypeFactoryImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeFactoryImpl {
    pub fn new() -> TypeFactoryImpl {
        let factory = TypeFactoryImpl {
            size_of_int: Cell::new(0),
            size_of_long: Cell::new(0),
            size_of_char: Cell::new(0),
            size_of_wchar: Cell::new(0),
            size_of_pointer: Cell::new(0),
            size_of_alt_pointer: Cell::new(0),
            // (kuna) 0 == "the cspec has not spoken"; `setup_sizes` fills these.
            size_of_short: Cell::new(0),
            size_of_long_long: Cell::new(0),
            size_of_float: Cell::new(0),
            size_of_double: Cell::new(0),
            size_of_long_double: Cell::new(0),
            enumsize: Cell::new(0),
            enumtype: Cell::new(type_metatype::TYPE_ENUM_UINT),
            align_map: RefCell::new(Vec::new()),
            max_basetype_size: Cell::new(16),
            truncate_big_endian: Cell::new(false),
            store: RefCell::new(FactoryStore::new()),
            model_context: RefCell::new(None),
            manager: RefCell::new(None),
            remote_types: RefCell::new(None),
            graph: GraphStore::new(),
            abi_cache: RefCell::new(BTreeMap::new()),
            building_core: Cell::new(false),
            host_decode: Cell::new(false),
            host_program: Cell::new(None),
            host_definitions: RefCell::new(Vec::new()),
            pending_host_sources: RefCell::new(Vec::new()),
        };
        factory.set_default_alignment_map();
        factory
    }

    /// Publish an owned draft using this factory's graph and alignment policy.
    pub fn intern(&self, draft: Datatype) -> KunaResult<TypeRoot> {
        self.find_add(draft)
    }

    pub fn set_proto_context(&self, defaultfp: Option<Rc<crate::fspec::ProtoModel>>, manager: Rc<kuna_base::space::AddrSpaceManager>) -> KunaResult<()> {
        let mut slot = self.model_context.try_borrow_mut().map_err(|_| KunaError::lowlevel("Type factory model context busy"))?;
        if let Some(context) = slot.as_ref() {
            if !Rc::ptr_eq(context.manager(), &manager) { return Err(KunaError::lowlevel("Type factory model manager mismatch")); }
            self.graph.bind_model_context(context.id())?;
            context.set_default(defaultfp);
        } else {
            let context = crate::fspec::ModelContext::new(manager.clone());
            self.graph.bind_model_context(context.id())?;
            context.set_default(defaultfp);
            *slot = Some(context);
        }
        *self.manager.borrow_mut() = Some(manager);
        Ok(())
    }

    /// Attach the architecture's live selection context; already-declared code
    /// retains its immutable model binding across future default changes.
    pub fn set_model_context(&self, context: Rc<crate::fspec::ModelContext>) -> KunaResult<()> {
        let mut slot = self.model_context.try_borrow_mut()
            .map_err(|_| KunaError::lowlevel("Type factory model context busy"))?;
        self.graph.bind_model_context(context.id())?;
        *self.manager.borrow_mut() = Some(context.manager().clone());
        *slot = Some(context);
        Ok(())
    }

    pub fn register_proto_model(&self, model: Rc<crate::fspec::ProtoModel>) {
        if let Some(context) = self.model_context.borrow().as_ref() { context.register_model(model); }
    }

    fn publish_draft(&self, root: &TypeRoot, draft: Datatype) -> KunaResult<TypeRoot> {
        // Construction setters and a fully decoded replacement body are explicit
        // source transactions. Pending correction remains distinct from initial
        // completion, including a sized aggregate explicitly kept incomplete;
        // GraphStore owns validation and failure attribution.
        if self.state(root)? == TypeState::Pending { self.correct_pending(root, draft)?; }
        else { self.complete(root, draft)?; }
        Ok(root.clone())
    }

    // -- Size configuration --------------------------------------------------

    pub fn set_max_basetype_size(&self, sz: int4) {
        self.max_basetype_size.set(sz);
    }

    pub fn set_truncate_big_endian(&self, big: bool) {
        self.truncate_big_endian.set(big);
    }

    pub fn set_default_alignment_map(&self) {
        let mut m = vec![1; 9];
        m[1] = 1;
        m[2] = 2;
        m[3] = 2;
        m[4] = 4;
        m[5] = 4;
        m[6] = 4;
        m[7] = 4;
        m[8] = 8;
        *self.align_map.borrow_mut() = m;
    }

    pub fn alignment_map_is_empty(&self) -> bool {
        self.align_map.borrow().is_empty()
    }

    pub fn decode_alignment_map(&self, entries: &[(int4, int4)]) -> KunaResult<()> {
        let mut m: Vec<int4> = Vec::new();
        for &(sz, val) in entries {
            while (m.len() as int4) <= sz {
                m.push(-1);
            }
            m[sz as usize] = val;
        }
        if m.is_empty() {
            return Err(KunaError::lowlevel("Alignment map empty"));
        }
        m[0] = 1;
        let mut cur_align = 1;
        for sz in 1..m.len() {
            let tmp_align = m[sz];
            if tmp_align == -1 {
                m[sz] = cur_align; // Copy alignment from nearest explicitly set value
            } else {
                cur_align = tmp_align;
            }
        }
        *self.align_map.borrow_mut() = m;
        Ok(())
    }

    pub fn setup_sizes(
        &self,
        stack_pointer_size: Option<int4>,
        default_data_addr_size: int4,
        default_size: int4,
    ) {
        if self.size_of_int.get() == 0 {
            let mut s = 1; // Default if we can't find a better value
            if let Some(sp) = stack_pointer_size {
                s = sp;
                if s > 4 {
                    s = 4; // "int" is rarely bigger than 4 bytes
                }
            }
            self.size_of_int.set(s);
        }
        if self.size_of_long.get() == 0 {
            self.size_of_long
                .set(if self.size_of_int.get() == 4 { 8 } else { self.size_of_int.get() });
        }
        if self.size_of_char.get() == 0 {
            self.size_of_char.set(1);
        }
        if self.size_of_wchar.get() == 0 {
            self.size_of_wchar.set(2);
        }
        if self.size_of_pointer.get() == 0 {
            self.size_of_pointer.set(default_data_addr_size);
        }
        // (kuna) Fill the widths the cspec left unset.  37 of the 107 vendored
        // cspecs carry no `<data_organization>` at all (every PowerPC 32-bit one
        // among them) and several carry only a subset, so these defaults are the
        // common case, not the exception.  The existing `size_of_long` fallback
        // above is deliberately untouched: it is read by type inference, not just
        // by rendering, so correcting it is a separate behavior change.
        if self.size_of_short.get() == 0 {
            self.size_of_short.set(2);
        }
        if self.size_of_long_long.get() == 0 {
            self.size_of_long_long.set(8);
        }
        if self.size_of_float.get() == 0 {
            self.size_of_float.set(4);
        }
        if self.size_of_double.get() == 0 {
            self.size_of_double.set(8);
        }
        if self.size_of_long_double.get() == 0 {
            // No `<long_double_size>` means the target has no wider floating type
            // to name, so `long double` is `double` -- the C rule when a compiler
            // aliases them (MSVC, ARM32 AAPCS).
            self.size_of_long_double.set(self.size_of_double.get());
        }
        // STUB(W4): the segmented far-pointer adjustment (glb->getSegmentOp) is a
        // W4 surface; without it sizeOfAltPointer stays 0, as for a flat space.
        if self.align_map.borrow().is_empty() {
            self.set_default_alignment_map();
        }
        if self.enumsize.get() == 0 {
            self.enumsize.set(default_size);
            self.enumtype.set(type_metatype::TYPE_ENUM_UINT);
        }
    }

    pub fn set_size_of_char(&self, s: int4) {
        self.size_of_char.set(s);
    }
    pub fn set_size_of_wchar(&self, s: int4) {
        self.size_of_wchar.set(s);
    }
    pub fn set_size_of_int(&self, s: int4) {
        self.size_of_int.set(s);
    }
    pub fn set_size_of_long(&self, s: int4) {
        self.size_of_long.set(s);
    }
    pub fn set_size_of_pointer(&self, s: int4) {
        self.size_of_pointer.set(s);
    }
    pub fn set_size_of_short(&self, s: int4) {
        self.size_of_short.set(s);
    }
    pub fn set_size_of_long_long(&self, s: int4) {
        self.size_of_long_long.set(s);
    }
    pub fn set_size_of_float(&self, s: int4) {
        self.size_of_float.set(s);
    }
    pub fn set_size_of_double(&self, s: int4) {
        self.size_of_double.set(s);
    }
    pub fn set_size_of_long_double(&self, s: int4) {
        self.size_of_long_double.set(s);
    }

    // -- Alignment queries (type.cc:3774-3798) -------------------------------

    fn alignment(&self, size: uint4) -> KunaResult<int4> {
        let m = self.align_map.borrow();
        if size as usize >= m.len() {
            if m.is_empty() {
                return Err(KunaError::lowlevel("TypeFactory alignment map not initialized"));
            }
            return Ok(m[m.len() - 1]);
        }
        Ok(m[size as usize])
    }

    fn primitive_align_size(&self, size: uint4) -> KunaResult<int4> {
        let align = self.alignment(size)?;
        let mut size = size;
        // C++ `uint4 mod = size % align;` — `align` is int4 but positive here.
        let mod_ = size % align as uint4;
        if mod_ != 0 {
            size += align as uint4 - mod_;
        }
        Ok(size as int4)
    }

    // -- Graph publication --------------------------------------------------

    /// Look up a unique source declaration, independently of its instance size.
    pub fn find_by_source_id(&self, n: &str, id: uint8) -> KunaResult<Option<TypeRoot>> {
        self.graph.find_source(n, id, false)
    }

    /// Exact native reference lookup. An absent size requests a fixed instance.
    pub fn find_by_instance(&self, n: &str, id: uint8, size: Option<int4>) -> Option<TypeRoot> {
        self.graph.find_instance(n, id, size.map_or(TypeInstance::Fixed, TypeInstance::Sized))
    }





    fn find_add(&self, mut ct: Datatype) -> KunaResult<TypeRoot> {
        if !ct.name.is_empty() && ct.id == 0 {
            return Err(KunaError::lowlevel(format!("Datatype must have a valid id: {}", ct.name)));
        }
        if ct.alignment < 0 {
            ct.align_size = self.primitive_align_size(ct.size as uint4)?;
            ct.alignment = self.alignment(ct.align_size as uint4)?;
        }
        if self.building_core.get() || ct.is_core_type() {
            ct.flags |= flags::coretype;
            self.graph.intern_core(ct)
        } else {
            self.get_type_void_impl()?;
            self.graph.intern(ct)
        }
    }

    fn is_big_endian_impl(&self) -> bool {
        self.truncate_big_endian.get()
    }



    fn set_name_impl(&self, ct: &TypeRoot, n: &str) -> KunaResult<TypeRoot> {
        let mut draft = ct.read().definition(ct.id())?.clone();
        draft.name = n.to_owned();
        draft.display_name = n.to_owned();
        if draft.id == 0 { draft.id = Datatype::hash_name(n); }
        self.find_add(draft)
    }

    fn set_display_format_impl(&self, ct: &TypeRoot, format: uint4) -> KunaResult<TypeRoot> {
        self.graph.set_display_format(ct, format)
    }

    fn assign_raw_fields_struct_impl(&self, ct: &TypeRoot, mut fd: Vec<TypeField>, mut bit: Vec<TypeBitField>) -> KunaResult<TypeRoot> {
        let (size, align, extra) = {
            let view = ct.read();
            assign_field_offsets(view.get(ct.id())?.graph, &mut fd, &mut bit)?
        };
        self.set_fields_struct(ct, fd, bit, size, align, extra)
    }

    fn assign_raw_fields_union_impl(&self, ct: &TypeRoot, mut fd: Vec<TypeField>) -> KunaResult<TypeRoot> {
        let (size, align) = {
            let view = ct.read();
            let node = view.get(ct.id())?;
            assign_union_field_offsets(node.graph, &mut fd, node.get_name())?
        };
        self.set_fields_union(ct, fd, size, align, 0)
    }

    fn set_fields_struct(
        &self,
        ct: &TypeRoot,
        fd: Vec<TypeField>,
        bit: Vec<TypeBitField>,
        new_size: int4,
        new_align: int4,
        extra_flags: uint4,
    ) -> KunaResult<TypeRoot> {
        if !matches!(self.state(ct)?, TypeState::Opaque | TypeState::Loading | TypeState::Pending | TypeState::Failed(_)) {
            return Err(KunaError::lowlevel("Can only set fields on an incomplete structure"));
        }
        if new_size < 0 || new_align <= 0 {
            return Err(KunaError::lowlevel("Invalid structure size or alignment"));
        }
        let mut newct = ct.read().definition(ct.id())?.clone();
        newct.set_struct_fields(fd, bit, new_size, new_align);
        newct.flags &= !flags::type_incomplete;
        newct.flags |= extra_flags
            & (flags::opaque_string
                | flags::variable_length
                | flags::type_incomplete
                | flags::has_bitfields);
        self.publish_draft(ct, newct)
    }

    fn set_fields_union(
        &self,
        ct: &TypeRoot,
        fd: Vec<TypeField>,
        new_size: int4,
        new_align: int4,
        extra_flags: uint4,
    ) -> KunaResult<TypeRoot> {
        if !matches!(self.state(ct)?, TypeState::Opaque | TypeState::Loading | TypeState::Pending | TypeState::Failed(_)) {
            return Err(KunaError::lowlevel("Can only set fields on an incomplete union"));
        }
        if new_size < 0 || new_align <= 0 {
            return Err(KunaError::lowlevel("Invalid union size or alignment"));
        }
        let mut newct = ct.read().definition(ct.id())?.clone();
        newct.set_union_fields(fd, new_size, new_align);
        newct.flags &= !flags::type_incomplete;
        newct.flags |= extra_flags & (flags::variable_length | flags::type_incomplete);
        self.publish_draft(ct, newct)
    }

    fn set_enum_values_impl(
        &self,
        ct: &TypeRoot,
        nmap: std::collections::BTreeMap<u64, String>,
    ) -> KunaResult<TypeRoot> {
        let mut newct = ct.read().definition(ct.id())?.clone();
        newct.set_name_map(nmap);
        newct.flags &= !flags::type_incomplete;
        self.publish_draft(ct, newct)
    }

    fn get_typedef_impl(&self, ct: &TypeRoot, name: &str, id: uint8, format: uint4) -> KunaResult<TypeRoot> {
        if id == 0 && format == ct.get_display_format() {
            let view = ct.read();
            let target = view.get(ct.id())?;
            if target.get_name() == name && target.get_display_name() == name {
                return Ok(ct.clone());
            }
        }
        let id = if id == 0 { Datatype::hash_name(name) } else { id };
        let alias = self.graph.reserve_alias_instance(name, id, self.graph.instance_of(ct), Some(ct.id()), false)?;
        let mut draft = Datatype::new_with_align(ct.get_size(), ct.get_alignment(), ct.get_metatype());
        draft.name = name.to_owned();
        draft.display_name = name.to_owned();
        draft.id = id;
        draft.kind = DatatypeKind::Alias;
        draft.typedef_imm = Some(ct.id());
        draft.set_display_format(format);
        self.complete(&alias, draft)?;
        Ok(alias)
    }

    fn destroy_type_impl(&self, ct: &TypeRoot) -> KunaResult<()> {
        match self.state(ct)? {
            TypeState::Opaque | TypeState::Loading | TypeState::Failed(_) => {
                self.fail(ct, "Datatype construction abandoned".to_owned())
            }
            _ => {
                self.retire_inferred(std::slice::from_ref(ct))?;
                Ok(())
            }
        }
    }

    // -- Core-type setup (type.cc:3637-3707) ---------------------------------

    pub fn set_core_type(
        &self,
        name: &str,
        size: int4,
        meta: type_metatype,
        chartp: bool,
    ) -> KunaResult<()> {
        let previous = self.building_core.replace(true);
        let result = (|| {
        let _ct = if chartp {
            if size == 1 {
                self.make_type_char(name)?
            } else {
                self.make_type_unicode(name, size, meta)?
            }
        } else if meta == type_metatype::TYPE_CODE {
            self.make_type_code_named(name)?
        } else if meta == type_metatype::TYPE_VOID {
            self.get_type_void()?
        } else {
            self.get_base_named(size, meta, name)?
        };
        Ok(())
        })();
        self.building_core.set(previous);
        result
    }

    pub fn clear_noncore(&self) -> KunaResult<()> {
        let mut cache = self.abi_cache.try_borrow_mut().map_err(|_| KunaError::lowlevel("Datatype ABI cache busy"))?;
        self.graph.flush()?;
        cache.clear();
        Ok(())
    }

    pub fn cache_core_types(&self) -> KunaResult<()> {
        self.get_type_void_impl()?;
        self.graph.seal_core()?;
        use type_metatype::*;
        let mut entries = self.graph.core_roots();
        // Preserve primitive cache preference without a live ordered index.
        entries.sort_unstable_by(|left, right| {
            left.get_sub_meta().cmp(&right.get_sub_meta())
                .then_with(|| right.get_size().cmp(&left.get_size()))
                .then_with(|| left.get_id().cmp(&right.get_id()))
        });
        let float_idx = TYPE_FLOAT.as_i32();
        let mut store = self.store.borrow_mut();
        for ct in entries {
            if !ct.is_core_type() {
                continue;
            }
            if ct.get_size() > 8 {
                if ct.get_metatype() == TYPE_FLOAT {
                    if ct.get_size() == 10 {
                        store.typecache10 = Some(ct.clone());
                    } else if ct.get_size() == 16 {
                        store.typecache16 = Some(ct.clone());
                    }
                }
                continue;
            }
            let meta = ct.get_metatype();
            // C++ switch with fallthrough TYPE_INT -> TYPE_UINT -> common.
            let mut handled_char = false;
            if meta == TYPE_INT || meta == TYPE_UINT {
                if meta == TYPE_INT && ct.get_size() == 1 && !ct.is_ascii() {
                    store.type_nochar = Some(ct.clone());
                }
                if ct.is_enum_type() {
                    continue; // Conceivably an enumeration
                }
                if ct.is_char_print() {
                    if ct.get_size() < 5 {
                        store.charcache[ct.get_size() as usize] = Some(ct.clone());
                    }
                    if ct.is_ascii() {
                        // Char is preferred over other int types.
                        let col = (ct.get_metatype().as_i32() - float_idx) as usize;
                        store.typecache[ct.get_size() as usize][col] = Some(ct.clone());
                    }
                    // Other character types (UTF16,UTF32) are not preferred.
                    continue;
                }
                handled_char = true; // fall through to the common cache step
            }
            // Common step for VOID/UNKNOWN/BOOL/CODE/FLOAT (and the INT/UINT
            // fallthrough that did not `continue` above).
            if handled_char
                || matches!(meta, TYPE_VOID | TYPE_UNKNOWN | TYPE_BOOL | TYPE_CODE | TYPE_FLOAT)
            {
                let row = ct.get_size() as usize;
                let col = (ct.get_metatype().as_i32() - float_idx) as usize;
                if store.typecache[row][col].is_none() {
                    store.typecache[row][col] = Some(ct.clone());
                }
            }
        }
        Ok(())
    }

    fn with_host_decode<T>(&self, decode: impl FnOnce() -> KunaResult<T>) -> KunaResult<T> {
        let previous = self.host_decode.replace(true);
        let length = self.pending_host_sources.borrow().len();
        let mut guard = HostDecodeGuard { enabled: &self.host_decode, previous,
            pending: &self.pending_host_sources, length, keep_pending: false };
        let value = decode()?;
        if !previous {
            // Initial recursive completion is expected. An authoritative rewrite
            // after an earlier decoded definition is not a fresh receipt for it.
            let mut pending = self.pending_host_sources.borrow_mut();
            // Validate the complete batch before installing any receipt. A fresh
            // full definition may itself correct a pending root before enqueueing.
            for (id, source, epoch) in pending.iter() {
                if *epoch != self.graph.host_mutation_epoch() {
                    return Err(KunaError::decoder("Host datatype changed after authenticated definition decode"));
                }
                self.graph.validate_host_source_binding(&self.graph.root(*id)?, source)?;
            }
            for (id, source, _) in pending.drain(..) {
                self.graph.bind_host_source(&self.graph.root(id)?, source)?;
            }
        }
        guard.keep_pending = previous;
        Ok(value)
    }

    pub(crate) fn decode_host_type(&self, decoder: &mut dyn Decoder) -> KunaResult<TypeRoot> {
        self.with_host_decode(|| self.decode_type(decoder))
    }

    pub(crate) fn decode_host_core_types(&self, decoder: &mut dyn Decoder) -> KunaResult<()> {
        self.with_host_decode(|| self.decode_core_type_definitions(decoder))?;
        self.cache_core_types()
    }

    /// Inspect the current open element, then leave its ordinary attribute
    /// cursor unchanged for the existing decoder. Only real host entrypoints
    /// enable this receipt path; a local XML attribute cannot confer ownership.
    fn decode_host_source(&self, decoder: &mut dyn Decoder) -> KunaResult<Option<HostTypeSource>> {
        if !self.host_decode.get() { return Ok(None); }
        let (mut program, mut revision, mut id, mut size) = (None, None, None, None);
        let (mut kind, mut scope, mut binding) = (None, None, None);
        let mut seen = 0u8;
        loop {
            let attribute = decoder.get_next_attribute_id()?;
            if attribute == 0 { break; }
            let bit = if attribute == ATTRIB_KUNA_SOURCE_PROGRAM.get_id() { 1 }
                else if attribute == ATTRIB_KUNA_SOURCE_REVISION.get_id() { 2 }
                else if attribute == ATTRIB_KUNA_SOURCE_KIND.get_id() { 4 }
                else if attribute == ATTRIB_KUNA_SOURCE_SIZE.get_id() { 8 }
                else if attribute == ATTRIB_KUNA_SOURCE_SCOPE.get_id() { 16 }
                else if attribute == ATTRIB_KUNA_SOURCE_BINDING.get_id() { 32 }
                else { 0 };
            if bit != 0 && seen & bit != 0 { return Err(KunaError::decoder("Duplicate host datatype source attribute")); }
            seen |= bit;
            match bit {
                1 => program = Some(decoder.read_unsigned_integer()?),
                2 => revision = Some(decoder.read_unsigned_integer()?),
                4 => kind = Some(String::from_utf8(decoder.read_string()?).map_err(|_| KunaError::decoder("Invalid host source kind"))?),
                8 => size = Some(int4::try_from(decoder.read_signed_integer()?).map_err(|_| KunaError::decoder("Host source width overflow"))?),
                16 => scope = Some(String::from_utf8(decoder.read_string()?).map_err(|_| KunaError::decoder("Invalid host source scope"))?),
                32 => binding = Some(String::from_utf8(decoder.read_string()?).map_err(|_| KunaError::decoder("Invalid host source binding"))?),
                _ if attribute == kuna_base::marshal::ATTRIB_ID.get_id() => {
                    if id.is_some() { return Err(KunaError::decoder("Duplicate host datatype identity")); }
                    id = Some(decoder.read_unsigned_integer()?);
                }
                _ => {}
            }
        }
        decoder.rewind_attributes();
        if seen == 0 { return Ok(None); }
        let (Some(program), Some(revision), Some(id), Some(size), Some(kind), Some(scope), Some(binding)) =
            (program, revision, id, size, kind, scope, binding)
        else { return Err(KunaError::decoder("Incomplete host datatype source receipt")); };
        let kind = match kind.as_str() {
            "program" => HostTypeSourceKind::Program,
            "builtin" => HostTypeSourceKind::Builtin,
            "transient" => HostTypeSourceKind::Transient,
            _ => return Err(KunaError::decoder("Unknown host datatype source kind")),
        };
        if (kind == HostTypeSourceKind::Transient) != !scope.is_empty()
            || (kind == HostTypeSourceKind::Builtin) != !binding.is_empty() {
            return Err(KunaError::decoder("Host source receipt violates producer scope"));
        }
        if self.host_program.get().is_some_and(|expected| expected != program) {
            return Err(KunaError::decoder("Host datatype belongs to another Program"));
        }
        self.host_program.set(Some(program));
        Ok(Some(HostTypeSource { program, revision, id, kind, size, scope, binding }))
    }

    fn decode_host_definition(&self, source: Option<HostTypeSource>,
        decode: impl FnOnce() -> KunaResult<TypeRoot>) -> KunaResult<TypeRoot>
    {
        let Some(source) = source else { return decode() };
        let length = self.host_definitions.borrow().len();
        self.host_definitions.borrow_mut().push(source);
        let _guard = HostDefinitionGuard { definitions: &self.host_definitions, length };
        let result = decode();
        let source = self.host_definitions.borrow_mut().pop().expect("active host definition");
        let root = result?;
        // Some original decoder branches deliberately normalize a source type
        // to a different canonical identity (e.g. void), or to unknown. Those
        // roots do not authenticate an emitted source declaration.
        if root.get_id() == source.id && root.get_size() == source.size {
            let mut pending = self.pending_host_sources.borrow_mut();
            if let Some((_, previous, epoch)) = pending.iter_mut().find(|(id, _, _)| *id == root.id()) {
                if !previous.same_definition(&source) {
                    return Err(KunaError::decoder("Conflicting decoded host source datatype receipts"));
                }
                *epoch = self.graph.host_mutation_epoch();
            } else {
                pending.push((root.id(), source, self.graph.host_mutation_epoch()));
            }
        }
        Ok(root)
    }

    fn matches_host_source(&self, root: &TypeRoot, expected: &HostTypeSource) -> KunaResult<bool> {
        // Recursive and earlier completed definitions in this decode transaction
        // may resolve references, but do not yet confer externally visible ownership.
        if self.host_definitions.borrow().iter().any(|source| source.same_definition(expected))
            || self.pending_host_sources.borrow().iter().any(|(id, source, epoch)|
                *id == root.id() && *epoch == self.graph.host_mutation_epoch() && source.same_definition(expected)) {
            return Ok(true);
        }
        if self.graph.host_source_stale(root)? { return Ok(false); }
        let view = root.read();
        if let Some(actual) = view.host_source(root.id())? {
            if !actual.same_definition(expected) {
                return Err(KunaError::decoder("Datatype reference changes host source receipt"));
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub fn decode_type(&self, decoder: &mut dyn Decoder) -> KunaResult<TypeRoot> {
        self.decode_type_context(decoder, false, None, &mut Vec::new())
    }

    fn decode_type_context(&self, decoder: &mut dyn Decoder, forcecore: bool, request: Option<TypeInstance>, aliases: &mut Vec<AliasHeader>) -> KunaResult<TypeRoot> {
        if decoder.peek_element()? == ELEM_TYPEREF.get_id() {
            let elem_id = decoder.open_element()?;
            let source = self.decode_host_source(decoder)?;
            let mut newid: uint8 = 0;
            let mut size: int4 = -1;
            let mut name: Vec<u8> = Vec::new();
            loop {
                let attrib_id = decoder.get_next_attribute_id()?;
                if attrib_id == 0 {
                    break;
                }
                if attrib_id == kuna_base::marshal::ATTRIB_ID.get_id() {
                    newid = decoder.read_unsigned_integer()?;
                } else if attrib_id == kuna_base::marshal::ATTRIB_SIZE.get_id() {
                    // A "size" attribute indicates a variable-length base.
                    size = decoder.read_signed_integer()? as int4;
                } else if attrib_id == kuna_base::marshal::ATTRIB_NAME.get_id() {
                    name = decoder.read_string()?;
                }
            }
            let newname = String::from_utf8_lossy(&name).into_owned();
            if newname.is_empty() {
                return Err(KunaError::decoder("<typeref> missing name"));
            }
            if newid == 0 {
                newid = Datatype::hash_name(&newname);
            }
            let instance = if size > 0 { TypeInstance::Sized(size) } else { TypeInstance::Fixed };
            if request.is_some_and(|expected| expected != instance) {
                return Err(KunaError::decoder("Datatype reference violates requested instance"));
            }
            let ct = self
                .find_by_id_or_remote(&newname, newid, instance, forcecore, aliases, source.as_ref())?
                .ok_or_else(|| {
                    KunaError::lowlevel(format!("Unable to resolve type: {newname}"))
                })?;
            decoder.close_element(elem_id)?;
            return Ok(ct);
        }
        self.decode_type_no_ref_context(decoder, forcecore, request, aliases)
    }

    fn find_by_id_or_remote(
        &self,
        n: &str,
        id: uint8,
        instance: TypeInstance,
        forcecore: bool,
        aliases: &mut Vec<AliasHeader>,
        source: Option<&HostTypeSource>,
    ) -> KunaResult<Option<TypeRoot>> {
        if let Some(ct) = self.graph.resolve_instance(n, id, instance)? {
            if source.map(|source| self.matches_host_source(&ct, source)).transpose()?.unwrap_or(true) {
                self.reserve_alias_headers(aliases, Some(instance), Some(ct.id()))?;
                return Ok(Some(ct));
            }
        }
        let remote = match self.remote_types.borrow().clone() {
            Some(r) => r,
            None => return Ok(None),
        };
        let manager = match self.manager.borrow().clone() {
            Some(m) => m,
            None => return Ok(None),
        };
        let mut dec = kuna_base::marshal::PackedDecode::new(&manager);
        if !remote.fetch_data_type(n, id, &mut dec)? {
            return Ok(None);
        }
        let ct = self.with_host_decode(|| self.decode_type_context(&mut dec, forcecore, Some(instance), aliases))?;
        if ct.read().get(ct.id())?.get_name() != n || ct.get_id() != id {
            return Err(KunaError::decoder("Remote datatype reply changes source identity"));
        }
        if source.map(|source| self.matches_host_source(&ct, source)).transpose()?.is_some_and(|matches| !matches) {
            return Err(KunaError::decoder("Remote datatype definition lacks requested source receipt"));
        }
        Ok(Some(ct))
    }

    fn reserve_alias_headers(&self, aliases: &mut [AliasHeader], actual: Option<TypeInstance>, target: Option<TypeId>) -> KunaResult<()> {
        for alias in aliases.iter() {
            if let (Some(expected), Some(actual)) = (alias.constraint, actual) {
                if expected != actual { return Err(KunaError::decoder("Typedef target violates requested instance")); }
            }
        }
        let mut target = target;
        for alias in aliases.iter_mut().rev() {
            if alias.root.is_some() { continue; }
            let root = self.graph.reserve_alias_instance(&alias.name, alias.id, actual.or(alias.constraint), target, alias.core)?;
            alias.loading = matches!(self.state(&root)?, TypeState::Opaque | TypeState::Failed(_));
            if alias.loading { self.begin(&root)?; }
            target = Some(root.id());
            alias.root = Some(root);
        }
        Ok(())
    }

    pub fn set_remote_type_fetch(&self, remote: Option<Rc<dyn RemoteTypeFetch>>) {
        *self.remote_types.borrow_mut() = remote;
    }

    pub fn decode_core_types(&self, decoder: &mut dyn Decoder) -> KunaResult<()> {
        self.decode_core_type_definitions(decoder)?;
        self.cache_core_types()
    }

    fn decode_core_type_definitions(&self, decoder: &mut dyn Decoder) -> KunaResult<()> {
        let elem_id = decoder.open_element_id(&ELEM_CORETYPES)?;
        while decoder.peek_element()? != 0 {
            self.decode_type_no_ref(decoder, true)?;
        }
        decoder.close_element(elem_id)
    }

    fn decode_type_no_ref(
        &self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
    ) -> KunaResult<TypeRoot> {
        self.decode_type_no_ref_context(decoder, forcecore, None, &mut Vec::new())
    }

    fn decode_type_no_ref_context(&self, decoder: &mut dyn Decoder, forcecore: bool, request: Option<TypeInstance>, aliases: &mut Vec<AliasHeader>) -> KunaResult<TypeRoot> {
        use type_metatype::*;
        let elem_id = decoder.open_element()?;
        let source = self.decode_host_source(decoder)?;
        self.decode_host_definition(source, || {
        if elem_id == kuna_base::marshal::ELEM_VOID.get_id() {
            if request.is_some_and(|expected| expected != TypeInstance::Fixed) { return Err(KunaError::decoder("Void has no sized instance")); }
            let ct = self.get_type_void_impl()?;
            self.reserve_alias_headers(aliases, Some(TypeInstance::Fixed), Some(ct.id()))?;
            decoder.close_element(elem_id)?;
            return Ok(ct);
        }
        if elem_id == ELEM_DEF.get_id() {
            return self.decode_typedef(decoder, elem_id, forcecore, request, aliases);
        }
        let mut b = Self::decode_wire_type_attribs(decoder, forcecore)?;
        let meta = b.metatype.ok_or_else(|| {
            KunaError::decoder("type element missing metatype attribute")
        })?;
        if meta == TYPE_CODE && decoder.peek_element()? != 0 { b.varlength = true; }
        let instance = if b.varlength { TypeInstance::Sized(b.size) } else { TypeInstance::Fixed };
        if request.is_some_and(|expected| expected != instance) {
            return Err(KunaError::decoder("Datatype definition violates requested instance"));
        }
        self.reserve_alias_headers(aliases, Some(instance), None)?;
        let ct = match meta {
            TYPE_PTR => {
                let ptrto = self.decode_type(decoder)?;
                let mut draft = self.build_pointer(b.size, ptrto, b.wordsize.max(1) as uint4, b.spaceid.clone());
                draft.flags |= b.extra_flags(forcecore);
                b.apply_names(&mut draft);
                self.finish_pointer(draft)?
            }
            TYPE_PTRREL => {
                // Three children: ptrto, parent, <off> (type.cc:3024-3053).
                let ptrto = self.decode_type(decoder)?;
                let parent = self.decode_type(decoder)?;
                let off_el = decoder.open_element_id(&kuna_base::marshal::ELEM_OFF)?;
                let off = decoder
                    .read_signed_integer_id(&kuna_base::marshal::ATTRIB_CONTENT)?
                    as int4;
                decoder.close_element(off_el)?;
                let mut draft = self.build_pointer_rel(
                    b.size,
                    ptrto,
                    b.wordsize.max(1) as uint4,
                    parent,
                    off,
                    b.spaceid.clone(),
                );
                draft.flags |= b.extra_flags(forcecore);
                b.apply_names(&mut draft);
                self.find_add(draft)?
            }
            TYPE_ARRAY => {
                let arrayof = self.decode_type(decoder)?;
                if b.arraysize <= 0 {
                    return Err(KunaError::lowlevel("Bad size for array"));
                }
                let mut draft = self.build_array(b.arraysize, arrayof);
                draft.flags |= b.extra_flags(forcecore);
                b.apply_names(&mut draft);
                self.find_add(draft)?
            }
            TYPE_ENUM_INT | TYPE_ENUM_UINT => {
                // Children: <val name=… value=…> (TypeEnum::decode, type.cc:1662-1699).
                let mut namemap = std::collections::BTreeMap::new();
                while decoder.peek_element()? != 0 {
                    let sub = decoder.open_element()?;
                    let mut nm: Vec<u8> = Vec::new();
                    let mut val: i64 = 0;
                    loop {
                        let aid = decoder.get_next_attribute_id()?;
                        if aid == 0 {
                            break;
                        }
                        if aid == kuna_base::marshal::ATTRIB_NAME.get_id() {
                            nm = decoder.read_string()?;
                        } else if aid == kuna_base::marshal::ATTRIB_VALUE.get_id() {
                            val = decoder.read_signed_integer()?;
                        }
                    }
                    let mask = kuna_base::address::calc_mask(b.size);
                    namemap.insert(
                        (val as u64) & mask,
                        String::from_utf8_lossy(&nm).into_owned(),
                    );
                    decoder.close_element_skipping(sub)?;
                }
                let mut en = Datatype::new(b.size, meta);
                en.metatype = if meta == TYPE_ENUM_INT { TYPE_INT } else { TYPE_UINT };
                en.flags |= flags::enumtype | b.extra_flags(forcecore);
                en.kind = DatatypeKind::Enum { namemap };
                b.apply_names(&mut en);
                self.find_add(en)?
            }
            TYPE_STRUCT => return self.decode_composite(decoder, &b, forcecore, false, elem_id),
            TYPE_UNION => return self.decode_composite(decoder, &b, forcecore, true, elem_id),
            TYPE_CODE => return self.decode_code(decoder, &b, forcecore, elem_id),
            TYPE_VOID => self.get_type_void_impl()?,
            TYPE_SPACEBASE | TYPE_PARTIALUNION | TYPE_PARTIALSTRUCT | TYPE_PARTIALENUM => {
                // Never sent by the Java side (C++-internal metatypes); consume
                // any children and fall back to an unknown base of the size.
                while decoder.peek_element()? != 0 {
                    let sub = decoder.open_element()?;
                    decoder.close_element_skipping(sub)?;
                }
                self.get_base(b.size.max(1), TYPE_UNKNOWN)?
            }
            // int/uint/float/bool/unknown: char/utf variants first, else TypeBase.
            _ => {
                if b.char_flag && b.size == 1 {
                    let mut tc = Datatype::new(1, meta);
                    tc.flags |= flags::chartype | b.extra_flags(forcecore);
                    tc.submeta = if meta == TYPE_INT {
                        sub_metatype::SUB_INT_CHAR
                    } else {
                        sub_metatype::SUB_UINT_CHAR
                    };
                    b.apply_names(&mut tc);
                    self.find_add(tc)?
                } else if b.utf_flag || b.char_flag {
                    let mut tu = Datatype::new(b.size, meta);
                    match b.size {
                        2 => tu.flags |= flags::utf16,
                        4 => tu.flags |= flags::utf32,
                        1 => tu.flags |= flags::chartype,
                        _ => {}
                    }
                    tu.flags |= b.extra_flags(forcecore);
                    tu.submeta = if meta == TYPE_INT {
                        sub_metatype::SUB_INT_UNICODE
                    } else {
                        sub_metatype::SUB_UINT_UNICODE
                    };
                    b.apply_names(&mut tu);
                    self.find_add(tu)?
                } else {
                    let mut tb = Datatype::new(b.size, meta);
                    tb.flags |= b.extra_flags(forcecore);
                    b.apply_names(&mut tb);
                    self.find_add(tb)?
                }
            }
        };
        decoder.close_element(elem_id)?;
        Ok(ct)
        })
    }

    fn decode_code(&self, decoder: &mut dyn Decoder, b: &WireTypeAttribs, forcecore: bool, elem_id: u32) -> KunaResult<TypeRoot> {
        let mut draft = Datatype::new_with_align(b.size.max(1), 1, type_metatype::TYPE_CODE);
        b.apply_names(&mut draft);
        draft.flags |= b.extra_flags(forcecore) | flags::type_incomplete;
        draft.kind = DatatypeKind::Code { proto: None };
        let root = if forcecore || b.core { self.graph.intern_core(draft.clone())? }
            else { self.intern(draft.clone())? };
        let loading = matches!(self.state(&root)?, TypeState::Opaque | TypeState::Failed(_));
        if loading { self.begin(&root)?; }
        let result: KunaResult<Datatype> = (|| {
            let proto = if decoder.peek_element()? != 0 {
                let logical = crate::fspec::decode_logical_callable(decoder, self)?;
                Some(logical)
            } else { None };
            draft.kind = DatatypeKind::Code { proto };
            draft.flags &= !flags::type_incomplete;
            decoder.close_element(elem_id)?;
            Ok(draft)
        })();
        if let Err(error) = &result { if loading && matches!(self.state(&root)?, TypeState::Loading) { self.fail(&root, error.to_string())?; } }
        self.publish_draft(&root, result?)
    }

    fn decode_typedef(&self, decoder: &mut dyn Decoder, elem_id: u32, forcecore: bool, request: Option<TypeInstance>, aliases: &mut Vec<AliasHeader>) -> KunaResult<TypeRoot> {
        let mut id: uint8 = 0;
        let mut name = String::new();
        let mut format: uint4 = 0;
        loop {
            let aid = decoder.get_next_attribute_id()?;
            if aid == 0 {
                break;
            }
            if aid == kuna_base::marshal::ATTRIB_ID.get_id() {
                id = decoder.read_unsigned_integer()?;
            } else if aid == kuna_base::marshal::ATTRIB_NAME.get_id() {
                name = String::from_utf8_lossy(&decoder.read_string()?).into_owned();
            } else if aid == kuna_base::marshal::ATTRIB_FORMAT.get_id() {
                let f = decoder.read_string()?;
                format = wire_integer_format(&String::from_utf8_lossy(&f));
            }
        }
        if name.is_empty() {
            let target = self.decode_type_context(decoder, forcecore, request, aliases)?;
            decoder.close_element(elem_id)?;
            return Ok(target);
        }
        if id == 0 { id = Datatype::hash_name(&name); }
        if aliases.iter().any(|alias| alias.name == name && alias.id == id) {
            return Err(KunaError::decoder("Impossible cyclic typedef header"));
        }
        aliases.push(AliasHeader { name, id, format, constraint: request, core: forcecore, root: None, loading: false });
        let result: KunaResult<Datatype> = (|| {
            let target = self.decode_type_context(decoder, forcecore, None, aliases)?;
            let header = aliases.last().expect("current alias header");
            let mut draft = Datatype::new_with_align(target.get_size(), target.get_alignment(), target.get_metatype());
            draft.name = header.name.clone(); draft.display_name = header.name.clone(); draft.id = header.id;
            draft.kind = DatatypeKind::Alias; draft.typedef_imm = Some(target.id());
            draft.set_display_format(header.format);
            if header.core { draft.flags |= flags::coretype; }
            decoder.close_element(elem_id)?;
            Ok(draft)
        })();
        let header = aliases.pop().expect("current alias header");
        if let Err(error) = &result {
            if let Some(root) = &header.root {
                if header.loading && matches!(self.state(root)?, TypeState::Loading) { self.fail(root, error.to_string())?; }
            }
        }
        let draft = result?;
        let root = header.root.ok_or_else(|| KunaError::decoder("Typedef target did not establish an instance"))?;
        self.publish_draft(&root, draft)
    }

    fn decode_composite(
        &self,
        decoder: &mut dyn Decoder,
        b: &WireTypeAttribs,
        forcecore: bool,
        is_union: bool,
        elem_id: u32,
    ) -> KunaResult<TypeRoot> {
        let meta = if is_union {
            type_metatype::TYPE_UNION
        } else {
            type_metatype::TYPE_STRUCT
        };
        let mut stub = Datatype::new_with_align(
            b.size,
            if b.alignment > 0 { b.alignment } else { self.alignment(b.size as uint4)? },
            meta,
        );
        stub.flags |= flags::type_incomplete | b.extra_flags(forcecore);
        stub.kind = if is_union {
            DatatypeKind::Union { field: Vec::new() }
        } else {
            DatatypeKind::Struct {
                field: Vec::new(),
                bitfield: Vec::new(),
            }
        };
        b.apply_names(&mut stub);
        let draft = stub;
        let stub = if forcecore || b.core { self.graph.intern_core(draft.clone())? }
            else { self.intern(draft.clone())? };
        let loading = matches!(self.state(&stub)?, TypeState::Opaque | TypeState::Failed(_));
        if loading { self.begin(&stub)?; }
        let result: KunaResult<Datatype> = (|| {
        let mut fd: Vec<TypeField> = Vec::new();
        let mut bit: Vec<TypeBitField> = Vec::new();
        while decoder.peek_element()? != 0 {
            let sub = decoder.open_element()?;
            let mut fname = String::new();
            let mut foffset: int4 = 0;
            let mut fid: Option<int4> = None;
            let mut ffirst: int4 = 0;
            let mut fsize: int4 = 0;
            loop {
                let aid = decoder.get_next_attribute_id()?;
                if aid == 0 {
                    break;
                }
                if aid == kuna_base::marshal::ATTRIB_NAME.get_id() {
                    fname =
                        String::from_utf8_lossy(&decoder.read_string()?).into_owned();
                } else if aid == kuna_base::marshal::ATTRIB_OFFSET.get_id() {
                    foffset = decoder.read_signed_integer()? as int4;
                } else if aid == kuna_base::marshal::ATTRIB_ID.get_id() {
                    fid = Some(decoder.read_signed_integer()? as int4);
                } else if aid == kuna_base::address::ATTRIB_FIRST.get_id() {
                    ffirst = decoder.read_signed_integer()? as int4;
                } else if aid == kuna_base::marshal::ATTRIB_SIZE.get_id() {
                    fsize = decoder.read_signed_integer()? as int4;
                }
            }
            let fct = self.decode_type(decoder)?;
            if sub == crate::prettyprint::ids::ELEM_BITFIELD.get_id() {
                // <bitfield name id offset size=numbits first=lsb> (type.cc:864-894).
                let mut bf = TypeBitField::new(
                    fid.unwrap_or(foffset),
                    fsize,
                    self.is_big_endian_impl(),
                    fname,
                    fct.id(),
                );
                bf.byte_offset = foffset;
                bf.least_sig_bit = ffirst;
                bf.byte_size = ((i64::from(ffirst) + i64::from(fsize) + 7) / 8) as int4;
                bit.push(bf);
            } else {
                fd.push(TypeField::new(
                    fid.unwrap_or(foffset),
                    foffset,
                    fname,
                    fct.id(),
                ));
            }
            decoder.close_element_skipping(sub)?;
        }
        let mut complete = draft;
        if is_union {
            complete.set_union_fields(fd, b.size, complete.alignment);
        } else {
            complete.set_struct_fields(fd, bit, b.size, complete.alignment);
        }
        complete.flags &= !flags::type_incomplete;
        decoder.close_element(elem_id)?;
        Ok(complete)
        })();
        if let Err(error) = &result { if loading && matches!(self.state(&stub)?, TypeState::Loading) { self.fail(&stub, error.to_string())?; } }
        self.publish_draft(&stub, result?)
    }

    fn decode_wire_type_attribs(
        decoder: &mut dyn Decoder,
        _forcecore: bool,
    ) -> KunaResult<WireTypeAttribs> {
        let mut b = WireTypeAttribs::default();
        loop {
            let aid = decoder.get_next_attribute_id()?;
            if aid == 0 {
                break;
            }
            if aid == kuna_base::marshal::ATTRIB_NAME.get_id() {
                b.name = String::from_utf8_lossy(&decoder.read_string()?).into_owned();
            } else if aid == crate::jumptable::ATTRIB_LABEL.get_id() {
                b.display =
                    String::from_utf8_lossy(&decoder.read_string()?).into_owned();
            } else if aid == kuna_base::marshal::ATTRIB_ID.get_id() {
                b.id = decoder.read_unsigned_integer()?;
            } else if aid == kuna_base::marshal::ATTRIB_SIZE.get_id() {
                b.size = decoder.read_signed_integer()? as int4;
            } else if aid == kuna_base::marshal::ATTRIB_METATYPE.get_id() {
                let m = decoder.read_string()?;
                b.metatype = Some(string2metatype(&String::from_utf8_lossy(&m))?);
            } else if aid == ATTRIB_CORE.get_id() {
                b.core = decoder.read_bool()?;
            } else if aid == ATTRIB_VARLENGTH.get_id() {
                b.varlength = decoder.read_bool()?;
            } else if aid == ATTRIB_ALIGNMENT.get_id() {
                b.alignment = decoder.read_signed_integer()? as int4;
            } else if aid == ATTRIB_OPAQUESTRING.get_id() {
                b.opaquestring = decoder.read_bool()?;
            } else if aid == ATTRIB_CHAR.get_id() {
                b.char_flag = decoder.read_bool()?;
            } else if aid == ATTRIB_UTF.get_id() {
                b.utf_flag = decoder.read_bool()?;
            } else if aid == ATTRIB_ARRAYSIZE.get_id() {
                b.arraysize = decoder.read_signed_integer()? as int4;
            } else if aid == kuna_base::marshal::ATTRIB_WORDSIZE.get_id() {
                b.wordsize = decoder.read_unsigned_integer()?;
            } else if aid == kuna_base::marshal::ATTRIB_SPACE.get_id() {
                b.spaceid = Some(decoder.read_space()?);
            }
        }
        if b.size < 0 {
            return Err(KunaError::decoder("Bad size for type"));
        }
        if b.id == 0 && !b.name.is_empty() {
            b.id = Datatype::hash_name(&b.name);
        }
        Ok(b)
    }

    // -- Dependency ordering (type.cc:3745-3773) ------------------------------

    pub fn dependent_order(&self) -> Vec<TypeRoot> {
        let entries = self.graph.roots();
        let mut deporder: Vec<TypeRoot> = Vec::with_capacity(entries.len());
        let mut mark = std::collections::HashSet::with_capacity(entries.len());
        let mut pending: Vec<(TypeRoot, usize)> = Vec::new();
        for ct in entries {
            if !mark.insert(ct.id()) {
                continue;
            }
            pending.push((ct, 0));
            while let Some((root, next_index)) = pending.last_mut() {
                // Borrow the canonical edge inventory, including callable,
                // alias, bitfield, relative-pointer and variant dependencies.
                // Only the next ID is copied; no datatype body is cloned.
                let next = {
                    let view = root.read();
                    view.dependencies(root.id())
                        .expect("published datatype has valid dependencies")
                        .get(*next_index)
                        .copied()
                };
                if let Some(id) = next {
                    *next_index += 1;
                    if mark.insert(id) {
                        let child = root.related(id)
                            .expect("published dependency belongs to the retained graph");
                        pending.push((child, 0));
                    }
                } else {
                    let (finished, _) = pending.pop().expect("postorder frame exists");
                    deporder.push(finished);
                }
            }
        }
        deporder
    }

    // -- Atomic / core getters (type.cc:4056-4198) ---------------------------

    fn get_type_void_impl(&self) -> KunaResult<TypeRoot> {
        let col = (type_metatype::TYPE_VOID.as_i32() - type_metatype::TYPE_FLOAT.as_i32()) as usize;
        if let Some(ct) = self.store.borrow().typecache[0][col].clone() { return Ok(ct); }
        let mut tv = Datatype::new_with_align(0, 1, type_metatype::TYPE_VOID);
        tv.name = "void".to_owned(); tv.display_name = tv.name.clone();
        tv.flags |= flags::coretype; tv.kind = DatatypeKind::Void;
        tv.id = Datatype::hash_name(&tv.name);
        let ct = self.find_add(tv)?;
        self.store.borrow_mut().typecache[0][col] = Some(ct.clone());
        Ok(ct)
    }

    fn make_type_char(&self, n: &str) -> KunaResult<TypeRoot> {
        // TypeChar(n): TypeBase(1,TYPE_INT,n), flags|=chartype, submeta=SUB_INT_CHAR.
        let mut tc = Datatype::new(1, type_metatype::TYPE_INT);
        tc.name = n.to_string();
        tc.display_name = n.to_string();
        tc.flags |= flags::chartype;
        tc.submeta = sub_metatype::SUB_INT_CHAR;
        tc.id = Datatype::hash_name(n);
        self.find_add(tc)
    }

    fn make_type_unicode(&self, nm: &str, sz: int4, m: type_metatype) -> KunaResult<TypeRoot> {
        // TypeUnicode(nm,sz,m): TypeBase(sz,m,nm); setflags(); submeta by INT/UINT.
        let mut tu = Datatype::new(sz, m);
        tu.name = nm.to_string();
        tu.display_name = nm.to_string();
        // setflags(): utf16/utf32/chartype by size.
        match sz {
            2 => tu.flags |= flags::utf16,
            4 => tu.flags |= flags::utf32,
            1 => tu.flags |= flags::chartype,
            _ => {}
        }
        tu.submeta = if m == type_metatype::TYPE_INT {
            sub_metatype::SUB_INT_UNICODE
        } else {
            sub_metatype::SUB_UINT_UNICODE
        };
        tu.id = Datatype::hash_name(nm);
        self.find_add(tu)
    }

    fn get_base_no_char_impl(&self, s: int4, m: type_metatype) -> KunaResult<TypeRoot> {
        if s == 1 && m == type_metatype::TYPE_INT {
            if let Some(nc) = self.store.borrow().type_nochar.clone() {
                return Ok(nc);
            }
        }
        self.get_base_impl(s, m)
    }

    fn get_base_impl(&self, s: int4, m: type_metatype) -> KunaResult<TypeRoot> {
        if s < 0 {
            return Err(KunaError::lowlevel(format!("getBase: negative data-type size {s}")));
        }
        let float_idx = type_metatype::TYPE_FLOAT.as_i32();
        if s < 9 {
            if m.as_i32() >= float_idx {
                let cached = self.store.borrow().typecache[s as usize][(m.as_i32() - float_idx) as usize]
                    .clone();
                if let Some(ct) = cached {
                    return Ok(ct);
                }
            }
        } else if m == type_metatype::TYPE_FLOAT {
            let cached = if s == 10 {
                self.store.borrow().typecache10.clone()
            } else if s == 16 {
                self.store.borrow().typecache16.clone()
            } else {
                None
            };
            if let Some(ct) = cached {
                return Ok(ct);
            }
        }
        if s > self.max_basetype_size.get() {
            // Create array of unknown bytes to match size.
            let unk = self.get_base_impl(1, type_metatype::TYPE_UNKNOWN)?;
            let arr = self.get_type_array_impl(s, unk)?;
            return Ok(arr);
        }
        // TypeBase(s,m): Datatype(s,-1,m).
        let tmp = Datatype::new(s, m);
        self.find_add(tmp)
    }

    fn get_base_named_impl(&self, s: int4, m: type_metatype, n: &str) -> KunaResult<TypeRoot> {
        let mut tmp = Datatype::new(s, m);
        tmp.name = n.to_string();
        tmp.display_name = n.to_string();
        tmp.id = Datatype::hash_name(n);
        self.find_add(tmp)
    }

    fn get_type_char_sized(&self, s: int4) -> KunaResult<TypeRoot> {
        if (0..5).contains(&s) {
            if let Some(res) = self.store.borrow().charcache[s as usize].clone() {
                return Ok(res);
            }
        }
        Err(KunaError::lowlevel("Request for unsupported character data-type"))
    }

    fn get_type_code_impl(&self) -> KunaResult<TypeRoot> {
        let code_col = (type_metatype::TYPE_CODE.as_i32() - type_metatype::TYPE_FLOAT.as_i32()) as usize;
        if let Some(ct) = self.store.borrow().typecache[1][code_col].clone() {
            return Ok(ct);
        }
        // TypeCode(): generic code object, markComplete().
        let mut tmp = Datatype::new_with_align(1, 1, type_metatype::TYPE_CODE);
        tmp.kind = DatatypeKind::Code { proto: None };
        // markComplete(): clear the type_incomplete flag (already clear here).
        tmp.flags &= !flags::type_incomplete;
        self.find_add(tmp)
    }

    fn make_type_code_proto(&self, proto: &crate::fspec::LogicalCallable) -> KunaResult<TypeRoot> {
        let mut tc = Datatype::new_with_align(1, 1, type_metatype::TYPE_CODE);
        tc.flags |= flags::variable_length;
        let mut logical = proto.clone();
        if logical.binding.model().has_this_pointer() { logical.flags |= crate::fspec::func_proto_flags::HAS_THISPTR; }
        if logical.binding.model().is_constructor() { logical.flags |= crate::fspec::func_proto_flags::IS_CONSTRUCTOR; }
        tc.kind = DatatypeKind::Code { proto: Some(logical) };
        self.find_add(tc)
    }





    fn make_type_code_named(&self, nm: &str) -> KunaResult<TypeRoot> {
        if nm.is_empty() {
            return self.get_type_code_impl();
        }
        let mut tmp = Datatype::new_with_align(1, 1, type_metatype::TYPE_CODE);
        tmp.kind = DatatypeKind::Code { proto: None };
        tmp.name = nm.to_string();
        tmp.display_name = nm.to_string();
        tmp.id = Datatype::hash_name(nm);
        tmp.flags &= !flags::type_incomplete;
        self.find_add(tmp)
    }

    // -- Pointer / composite construction (type.cc:4323-4471) ----------------

    fn build_pointer(&self, s: int4, pt: TypeRoot, ws: uint4, spaceid: Option<Rc<AddrSpace>>) -> Datatype {
        let mut p = Datatype::new(s, type_metatype::TYPE_PTR);
        p.flags = pt.inherit_for_pointer() & !flags::coretype;
        // calcSubmeta():
        let ptrto_meta = pt.get_metatype();
        match ptrto_meta {
            type_metatype::TYPE_STRUCT => {
                p.submeta = if pt.needs_resolution() {
                    sub_metatype::SUB_PTR
                } else {
                    sub_metatype::SUB_PTR_STRUCT
                };
            }
            type_metatype::TYPE_UNION => {
                p.submeta = sub_metatype::SUB_PTR_STRUCT;
            }
            type_metatype::TYPE_ARRAY => {
                p.flags |= flags::pointer_to_array;
            }
            _ => {}
        }
        if pt.needs_resolution() && ptrto_meta != type_metatype::TYPE_PTR {
            p.flags |= flags::needs_resolution;
        }
        p.kind = DatatypeKind::Pointer { ptrto: pt.id(), spaceid, truncate: None, wordsize: ws };
        p
    }

    fn finish_pointer(&self, mut draft: Datatype) -> KunaResult<TypeRoot> {
        let alt = self.size_of_alt_pointer.get();
        if alt > 0 && draft.size == alt && draft.size != self.size_of_pointer.get() {
            if let DatatypeKind::Pointer { ptrto, wordsize, truncate, spaceid } = &mut draft.kind {
                if truncate.is_none() {
                    let target = self.root(*ptrto)?;
                    let smaller = self.find_add(self.build_pointer(self.size_of_pointer.get(), target, *wordsize, spaceid.clone()))?;
                    *truncate = Some(smaller.id());
                    if self.truncate_big_endian.get() { draft.flags |= flags::truncate_bigendian; }
                }
            }
        }
        self.find_add(draft)
    }



    fn get_type_pointer_strip_array_impl(
        &self,
        s: int4,
        pt: TypeRoot,
        ws: uint4,
        spaceid: Option<Rc<AddrSpace>>,
    ) -> KunaResult<TypeRoot> {
        let mut pt = pt;
        if pt.has_stripped() {
            if let Some(st) = pt.get_stripped() {
                pt = st;
            }
        }
        if pt.get_metatype() == type_metatype::TYPE_ARRAY {
            if let Some(base) = pt.get_array_base() {
                pt = base; // Strip the first ARRAY type
            }
        }
        self.finish_pointer(self.build_pointer(s, pt, ws, spaceid))
    }

    fn get_type_pointer_impl(&self, s: int4, pt: TypeRoot, ws: uint4, spaceid: Option<Rc<AddrSpace>>) -> KunaResult<TypeRoot> {
        let mut pt = pt;
        if pt.has_stripped() {
            if let Some(st) = pt.get_stripped() {
                pt = st;
            }
        }
        self.finish_pointer(self.build_pointer(s, pt, ws, spaceid))
    }

    fn get_type_pointer_named_impl(
        &self,
        s: int4,
        pt: TypeRoot,
        ws: uint4,
        n: &str,
    ) -> KunaResult<TypeRoot> {
        let mut pt = pt;
        if pt.has_stripped() {
            if let Some(st) = pt.get_stripped() {
                pt = st;
            }
        }
        let mut tmp = self.build_pointer(s, pt, ws, None);
        tmp.name = n.to_string();
        tmp.display_name = n.to_string();
        tmp.id = Datatype::hash_name(n);
        self.finish_pointer(tmp)
    }

    fn resize_pointer_impl(&self, ptr: &TypeRoot, new_size: int4) -> KunaResult<TypeRoot> {
        let mut pt = ptr.get_ptr_to().ok_or_else(|| {
            KunaError::lowlevel("resizePointer: argument is not a pointer")
        })?;
        if pt.has_stripped() {
            if let Some(st) = pt.get_stripped() {
                pt = st;
            }
        }
        let ws = ptr.get_word_size().unwrap_or(1);
        self.finish_pointer(self.build_pointer(new_size, pt, ws, ptr.get_pointer_space()))
    }

    fn build_array(&self, as_: int4, ao: TypeRoot) -> Datatype {
        // Datatype(n*ao->getAlignSize(), ao->getAlignment(), TYPE_ARRAY).
        let size = as_ * ao.get_align_size();
        let mut a = Datatype::new_with_align(size, ao.get_alignment(), type_metatype::TYPE_ARRAY);
        // An array of size 1 is generally treated as the element data-type.
        if as_ == 1 {
            a.flags |= flags::needs_resolution;
        }
        a.kind = DatatypeKind::Array { arrayof: ao.id(), arraysize: as_ };
        a
    }

    fn get_type_array_impl(&self, as_: int4, ao: TypeRoot) -> KunaResult<TypeRoot> {
        let mut ao = ao;
        if ao.has_stripped() {
            if let Some(st) = ao.get_stripped() {
                ao = st;
            }
        }
        self.find_add(self.build_array(as_, ao))
    }

    fn get_type_struct_impl(&self, n: &str) -> KunaResult<TypeRoot> {
        self.reserve(n, if n.is_empty() { 0 } else { Datatype::hash_name(n) }, type_metatype::TYPE_STRUCT)
    }

    fn get_type_partial_struct_impl(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot> {
        let strip = self.get_base_impl(sz, type_metatype::TYPE_UNKNOWN)?;
        // TypePartialStruct(contain,off,sz,strip) (type.cc:2759-2780).
        // If the container is itself a partial struct, unwrap to the real parent
        // and fold the offset (`contain = partial->getParent(); off += ...`).
        let (contain, off) = if contain.get_metatype() == type_metatype::TYPE_PARTIALSTRUCT {
            let parent = contain.get_partial_base().unwrap_or_else(|| contain.clone());
            let poff = contain.get_partial_offset().unwrap_or(0);
            (parent, off + poff)
        } else {
            (contain, off)
        };
        let mut tps = Datatype::new_with_align(sz, -1, type_metatype::TYPE_PARTIALSTRUCT);
        tps.flags |= contain.inherit_for_partial() & !flags::coretype;
        tps.flags |= flags::has_stripped;
        // C++ type.cc:2776-2779: inherit the `has_bitfields` flag when the parent
        // struct contains bitfields that overlap the [offset, offset+sz) window.
        // Without this a 1-byte stack-struct member access (the bitfield byte of a
        // typed stack `struct`) reports `hasBitfields()==false`, so the bitfield
        // insert/extract rules (RuleBitFieldOut/In) never fire on stack locals.
        if contain.has_bitfields() && contain.has_bit_fields_in_range(off, sz) {
            tps.flags |= flags::has_bitfields;
        }
        tps.kind = DatatypeKind::PartialStruct { stripped: strip.id(), container: contain.id(), offset: off };
        self.find_add(tps)
    }

    fn get_type_union_impl(&self, n: &str) -> KunaResult<TypeRoot> {
        self.reserve(n, if n.is_empty() { 0 } else { Datatype::hash_name(n) }, type_metatype::TYPE_UNION)
    }

    fn get_type_partial_union_impl(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot> {
        let strip = self.get_base_impl(sz, type_metatype::TYPE_UNKNOWN)?;
        let mut tpu = Datatype::new_with_align(sz, -1, type_metatype::TYPE_PARTIALUNION);
        tpu.flags |= (contain.inherit_for_partial() & !flags::coretype) | flags::needs_resolution;
        tpu.kind = DatatypeKind::PartialUnion { stripped: strip.id(), container: contain.id(), offset: off };
        self.find_add(tpu)
    }

    fn get_type_enum_impl(&self, n: &str) -> KunaResult<TypeRoot> {
        self.get_type_enum_sized_impl(n, self.enumsize.get(), self.enumtype.get())
    }

    fn get_type_enum_sized_impl(
        &self,
        n: &str,
        s: int4,
        m: type_metatype,
    ) -> KunaResult<TypeRoot> {
        // TypeEnum(enumsize,enumtype,n): TypeBase(s,m,nm) -> submeta = base2sub(m),
        // then flags|=enumtype and metatype = INT/UINT.
        let mut tmp = Datatype::new(s, m); // submeta = base2sub(ENUM_INT/UINT)
        tmp.name = n.to_string();
        tmp.display_name = n.to_string();
        tmp.flags |= flags::enumtype | flags::type_incomplete;
        tmp.metatype =
            if m == type_metatype::TYPE_ENUM_INT { type_metatype::TYPE_INT } else { type_metatype::TYPE_UINT };
        tmp.kind = DatatypeKind::Enum { namemap: std::collections::BTreeMap::new() };
        tmp.id = Datatype::hash_name(n);
        self.find_add(tmp)
    }

    fn get_type_partial_enum_impl(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot> {
        let strip = self.get_base_impl(sz, type_metatype::TYPE_UNKNOWN)?;
        // C++ `TypePartialEnum(par,off,sz,strip)` (type.cc:2683) chains through
        // `TypeEnum(sz,TYPE_PARTIALENUM)` (type.hh:548): the `TypeBase(s,m)` base
        // sets `metatype=TYPE_PARTIALENUM` / `submeta=base2sub(TYPE_PARTIALENUM)=
        // SUB_UINT_PARTIALENUM`, then the `TypeEnum` ctor body **overrides**
        // `metatype = (TYPE_PARTIALENUM==TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT`
        // (so TYPE_UINT) and sets `flags |= enumtype` — leaving `submeta`
        // untouched.  The `TypePartialEnum` body then adds
        // `inheritForPartial()` and `has_stripped`.  `new_with_align` seeds
        // `metatype`/`submeta` from `TYPE_PARTIALENUM`; restore the enum
        // metatype override and the enum/stripped flags so the partial enum is
        // recognised as an enum by `is_enum_type()`/`getExactPiece`.
        let mut tpe = Datatype::new_with_align(sz, -1, type_metatype::TYPE_PARTIALENUM);
        tpe.metatype = type_metatype::TYPE_UINT;
        tpe.flags |= flags::enumtype;
        tpe.flags |= contain.inherit_for_partial() & !flags::coretype;
        tpe.flags |= flags::has_stripped;
        tpe.kind = DatatypeKind::PartialEnum { stripped: strip.id(), parent: contain.id(), offset: off };
        self.find_add(tpe)
    }

    fn get_type_spacebase_impl(
        &self,
        id: Rc<AddrSpace>,
        addr: &Address,
    ) -> KunaResult<TypeRoot> {
        // TypeSpacebase(id,addr,glb): Datatype(0,1,TYPE_SPACEBASE).
        let mut tsb = Datatype::new_with_align(0, 1, type_metatype::TYPE_SPACEBASE);
        tsb.kind = DatatypeKind::Spacebase { spaceid: Some(id), localframe: addr.clone() };
        self.find_add(tsb)
    }

    fn get_type_pointer_rel_impl(
        &self,
        parent_ptr: TypeRoot,
        ptr_to: TypeRoot,
        off: int4,
    ) -> KunaResult<TypeRoot> {
        let size = parent_ptr.get_size();
        let ws = parent_ptr.get_word_size().ok_or_else(|| {
            KunaError::lowlevel("getTypePointerRel: parentPtr is not a pointer")
        })?;
        let parent = parent_ptr
            .get_ptr_to()
            .ok_or_else(|| KunaError::lowlevel("getTypePointerRel: parentPtr is not a pointer"))?;
        let mut tp = self.build_pointer_rel(size, ptr_to, ws, parent, off, parent_ptr.get_pointer_space());
        // markEphemeral(typegrp): stripped = getTypePointer(size,ptrto,wordsize),
        // flags|=has_stripped, submeta=SUB_PTRREL_UNK if ptrto is TYPE_UNKNOWN.
        self.mark_ephemeral(&mut tp)?;
        self.find_add(tp)
    }

    #[allow(clippy::too_many_arguments)]
    fn get_type_pointer_rel_full_impl(
        &self,
        sz: int4,
        parent: TypeRoot,
        ptr_to: TypeRoot,
        ws: int4,
        off: int4,
        nm: &str,
    ) -> KunaResult<TypeRoot> {
        let mut tp = self.build_pointer_rel(sz, ptr_to, ws as uint4, parent, off, None);
        tp.name = nm.to_string();
        tp.display_name = nm.to_string();
        tp.id = Datatype::hash_name(nm);
        self.find_add(tp)
    }

    fn build_pointer_rel(
        &self,
        sz: int4,
        ptr_to: TypeRoot,
        ws: uint4,
        parent: TypeRoot,
        off: int4,
        spaceid: Option<Rc<AddrSpace>>,
    ) -> Datatype {
        // Start from the plain-pointer skeleton (inheritForPointer + calcSubmeta).
        let mut tp = self.build_pointer(sz, ptr_to.clone(), ws, None);
        // C++ TypePointerRel keeps `metatype == TYPE_PTR` internally — the
        // TypePointer base ctor sets it and the relative ctor never overrides it
        // ("Don't use TYPE_PTRREL internally", type.cc:3010).  The TYPE_PTRREL
        // metatype is ONLY a marshalling override (encodeBasic(TYPE_PTRREL,...),
        // type.cc:3109).  Using it as the live metatype mis-classifies a relative
        // pointer as a non-pointer in every `getMetatype()==TYPE_PTR` test
        // (RulePtrArith pointer-slot search, propagateType, etc.).
        tp.flags |= flags::is_ptrrel;
        // TypePointerRel uses SUB_PTRREL for the dependency ordering of a formal
        // relative pointer (markEphemeral lowers it to SUB_PTRREL_UNK).
        tp.submeta = sub_metatype::SUB_PTRREL;
        tp.kind = DatatypeKind::PointerRel {
            ptrto: ptr_to.id(),
            spaceid,
            wordsize: ws,
            stripped: None,
            parent: parent.id(),
            offset: off,
        };
        tp
    }

    fn mark_ephemeral(&self, tp: &mut Datatype) -> KunaResult<()> {
        let (id, ws, spaceid) = match &tp.kind {
            DatatypeKind::PointerRel { ptrto, wordsize, spaceid, .. } => (*ptrto, *wordsize, spaceid.clone()),
            _ => return Err(KunaError::lowlevel("markEphemeral: not a relative pointer")),
        };
        let ptrto = self.root(id)?;
        let unknown = ptrto.get_metatype() == type_metatype::TYPE_UNKNOWN;
        let stripped = self.get_type_pointer_impl(tp.size, ptrto, ws, spaceid)?;
        if let DatatypeKind::PointerRel { stripped: slot, .. } = &mut tp.kind { *slot = Some(stripped.id()); }
        tp.flags |= flags::has_stripped;
        if unknown { tp.submeta = sub_metatype::SUB_PTRREL_UNK; }
        Ok(())
    }

    fn get_type_pointer_with_space_impl(
        &self,
        size: int4,
        ptr_to: TypeRoot,
        wordsize: uint4,
        spc: Rc<AddrSpace>,
        nm: &str,
    ) -> KunaResult<TypeRoot> {
        let mut tp = self.build_pointer(size, ptr_to, wordsize, Some(spc));
        tp.name = nm.to_string();
        tp.display_name = nm.to_string();
        tp.id = if nm.is_empty() { 0 } else { Datatype::hash_name(nm) };
        self.finish_pointer(tp)
    }

    // -- Resizing / piece extraction (type.cc:4558-4610) ---------------------

    fn resize_integer_impl(&self, ct: TypeRoot, new_size: int4) -> KunaResult<TypeRoot> {
        if new_size == ct.get_size() {
            return Ok(ct);
        }
        let mut meta = ct.get_metatype();
        if meta != type_metatype::TYPE_INT && meta != type_metatype::TYPE_UINT {
            meta = type_metatype::TYPE_UINT;
        }
        if ct.is_char_print() {
            self.get_base_impl(new_size, meta)
        } else {
            self.get_base_no_char_impl(new_size, meta)
        }
    }

    fn get_exact_piece_impl(
        &self,
        ct: TypeRoot,
        offset: int4,
        size: int4,
    ) -> KunaResult<Option<TypeRoot>> {
        let mut last_type: Option<TypeRoot> = None;
        let mut last_off: int8 = 0;
        let mut cur_off: int8 = offset as int8;
        let mut ct = ct;
        loop {
            if (ct.get_size() as int8) < size as int8 + cur_off {
                break; // Range beyond end; construct partial around last data-type
            }
            if ct.get_size() == size {
                return Ok(Some(ct)); // Perfect size match
            }
            last_type = Some(ct.clone());
            last_off = cur_off;
            let (sub, new_off) = self.get_sub_type_via_factory(&ct, cur_off)?;
            cur_off = new_off;
            match sub {
                Some(next) => ct = next,
                None => break,
            }
        }
        if let Some(last_type) = last_type {
            let meta = last_type.get_metatype();
            match meta {
                type_metatype::TYPE_STRUCT
                | type_metatype::TYPE_ARRAY
                | type_metatype::TYPE_PARTIALSTRUCT => {
                    return Ok(Some(self.get_type_partial_struct_impl(
                        last_type,
                        last_off as int4,
                        size,
                    )?));
                }
                type_metatype::TYPE_UNION => {
                    return Ok(Some(self.get_type_partial_union_impl(
                        last_type,
                        last_off as int4,
                        size,
                    )?));
                }
                type_metatype::TYPE_PARTIALUNION => {
                    // Truncate to a smaller partial union: re-base into the parent.
                    let parent = last_type.get_partial_base().ok_or_else(|| {
                        KunaError::lowlevel("getExactPiece: partial union missing parent")
                    })?;
                    let part_off = last_type.get_partial_offset().unwrap_or(0);
                    return Ok(Some(self.get_type_partial_union_impl(
                        parent,
                        last_off as int4 + part_off,
                        size,
                    )?));
                }
                _ => {
                    if last_type.is_enum_type() && !last_type.has_stripped() {
                        return Ok(Some(self.get_type_partial_enum_impl(
                            last_type,
                            last_off as int4,
                            size,
                        )?));
                    }
                }
            }
        }
        Ok(None)
    }

    fn get_sub_type_via_factory(
        &self,
        ct: &TypeRoot,
        off: int8,
    ) -> KunaResult<(Option<TypeRoot>, int8)> {
        if ct.get_metatype() == type_metatype::TYPE_CODE {
            // factory != null -> getBase(1, TYPE_CODE), newoff = 0.
            let code = self.get_base_impl(1, type_metatype::TYPE_CODE)?;
            return Ok((Some(code), 0));
        }
        ct.get_sub_type(off)
    }

    fn concretize_impl(&self, ct: TypeRoot) -> KunaResult<TypeRoot> {
        if ct.get_metatype() == type_metatype::TYPE_CODE {
            if ct.get_size() != 1 {
                return Err(KunaError::lowlevel("Primitive code data-type that is not size 1"));
            }
            return self.get_base_impl(1, type_metatype::TYPE_UNKNOWN);
        }
        Ok(ct)
    }

    fn find_by_name_impl(&self, n: &str) -> Option<TypeRoot> {
        self.graph.find_by_name(n)
    }

    // -- Pointer drill-down (type.cc:1221-1258) ------------------------------

    #[allow(clippy::type_complexity)]
    pub fn down_chain(&self, ptr: &TypeRoot, off: int8, allow_array_wrap: bool)
        -> KunaResult<(Option<TypeRoot>, int8, Option<TypeRoot>, int8)>
    {
        // Read only the edges/scalars needed for this step, releasing the guard
        // before any pointer synthesis or recursion.
        let (target, wordsize, relative) = {
            let view = ptr.read();
            let node = view.get(ptr.id())?.effective()?;
            match &node.kind {
                DatatypeKind::Pointer { ptrto, wordsize, .. } => (*ptrto, *wordsize, None),
                DatatypeKind::PointerRel { ptrto, wordsize, parent, offset, .. } =>
                    (*ptrto, *wordsize, Some((*parent, *offset))),
                _ => return Ok((None, off, None, 0)),
            }
        };
        let ptrto = ptr.related(target)?;
        let Some((parent, offset)) = relative else {
            return self.down_chain_pointer(ptr, &ptrto, wordsize, off, allow_array_wrap);
        };
        let meta = ptrto.get_metatype();
        if off >= 0 && off < ptrto.get_size() as int8
            && matches!(meta, type_metatype::TYPE_STRUCT | type_metatype::TYPE_ARRAY)
        {
            return self.down_chain_pointer(ptr, &ptrto, wordsize, off, allow_array_wrap);
        }
        let parent = ptr.related(parent)?;
        let rel_off = (((off + offset as int8) as uint8) & kuna_base::address::calc_mask(ptr.get_size())) as int8;
        if rel_off < 0 || rel_off >= parent.get_size() as int8 { return Ok((None, off, None, 0)); }
        let original = self.get_type_pointer_impl(ptr.get_size(), parent, wordsize, ptr.get_pointer_space())?;
        if rel_off == 0 && offset != 0 { return Ok((Some(original), rel_off, None, 0)); }
        self.down_chain(&original, rel_off, allow_array_wrap)
    }

    #[allow(clippy::type_complexity)]
    fn down_chain_pointer(
        &self,
        ptr: &TypeRoot,
        ptrto: &TypeRoot,
        wordsize: uint4,
        mut off: int8,
        allow_array_wrap: bool,
    ) -> KunaResult<(Option<TypeRoot>, int8, Option<TypeRoot>, int8)> {
        let ptrto_size = ptrto.get_align_size() as int8;
        if off < 0 || off >= ptrto_size {
            // Check if we are wrapping.
            if ptrto_size != 0 && !ptrto.is_variable_length() {
                if !allow_array_wrap {
                    return Ok((None, off, None, 0));
                }
                // intb signOff = sign_extend(off, size*8 - 1); signOff %= ptrtoSize.
                let mut sign_off =
                    kuna_base::address::sign_extend(off, ptr.get_size() * 8 - 1) % ptrto_size;
                if sign_off < 0 {
                    sign_off += ptrto_size;
                }
                off = sign_off;
                if off == 0 {
                    // Wrapped and now at zero: consider this going down one level.
                    return Ok((Some(ptr.clone()), off, None, 0));
                }
            }
        }

        if ptrto.is_enum_type() {
            // Go "into" the enumeration.
            let tmp = self.get_base_impl(1, type_metatype::TYPE_UINT)?;
            let result = self.get_type_pointer_impl(ptr.get_size(), tmp, wordsize, ptr.get_pointer_space())?;
            return Ok((Some(result), 0, None, 0));
        }
        let meta = ptrto.get_metatype();
        let is_array = meta == type_metatype::TYPE_ARRAY;
        let mut par: Option<TypeRoot> = None;
        let mut par_off: int8 = 0;
        if is_array || meta == type_metatype::TYPE_STRUCT {
            par = Some(ptr.clone());
            par_off = off;
        }
        let (pt, new_off) = self.get_sub_type_via_factory(ptrto, off)?;
        off = new_off;
        let pt = match pt {
            Some(p) => p,
            None => return Ok((None, off, par, par_off)),
        };
        let result = if !is_array {
            self.get_type_pointer_strip_array_impl(ptr.get_size(), pt, wordsize, ptr.get_pointer_space())?
        } else {
            self.get_type_pointer_impl(ptr.get_size(), pt, wordsize, ptr.get_pointer_space())?
        };
        Ok((Some(result), off, par, par_off))
    }
}

impl TypeFactory for TypeFactoryImpl {
    fn root(&self, id: TypeId) -> KunaResult<TypeRoot> { self.graph.root(id) }
    fn find_by_source_id(&self, name: &str, host_id: u64) -> KunaResult<Option<TypeRoot>> {
        TypeFactoryImpl::find_by_source_id(self, name, host_id)
    }
    fn find_by_instance(&self, name: &str, host_id: u64, size: Option<int4>) -> Option<TypeRoot> {
        TypeFactoryImpl::find_by_instance(self, name, host_id, size)
    }
    fn intern(&self, draft: Datatype) -> KunaResult<TypeRoot> { TypeFactoryImpl::intern(self, draft) }
    fn reserve(&self, name: &str, host_id: u64, meta: type_metatype) -> KunaResult<TypeRoot> {
        self.get_type_void_impl()?;
        self.graph.reserve(name, host_id, meta, false)
    }
    fn reserve_alias(&self, name: &str, host_id: u64) -> KunaResult<TypeRoot> {
        self.get_type_void_impl()?;
        self.graph.reserve_alias(name, host_id)
    }
    fn reserve_inferred(&self, name: &str, host_id: u64, meta: type_metatype) -> KunaResult<TypeRoot> {
        self.get_type_void_impl()?;
        self.graph.reserve(name, host_id, meta, true)
    }
    fn retire_inferred(&self, roots: &[TypeRoot]) -> KunaResult<Vec<TypeId>> {
        let affected = self.graph.retire_inferred(roots)?;
        let mut cache = self.abi_cache.borrow_mut();
        for id in &affected { cache.remove(id); }
        Ok(affected)
    }
    fn begin(&self, root: &TypeRoot) -> KunaResult<()> { self.graph.begin(root) }
    fn complete(&self, root: &TypeRoot, draft: Datatype) -> KunaResult<()> { self.graph.complete(root, draft) }
    fn correct_pending(&self, root: &TypeRoot, draft: Datatype) -> KunaResult<()> { self.graph.correct_pending(root, draft) }
    fn fail(&self, root: &TypeRoot, reason: String) -> KunaResult<()> { self.graph.fail(root, reason) }
    fn state(&self, root: &TypeRoot) -> KunaResult<TypeState> { self.graph.state(root) }
    fn decode_type(&self, decoder: &mut dyn Decoder) -> KunaResult<TypeRoot> { TypeFactoryImpl::decode_type(self, decoder) }
    fn model_context_id(&self) -> Option<crate::fspec::ModelContextId> {
        self.model_context.borrow().as_ref().map(|context| context.id())
    }
    fn model_binding(&self, name: Option<&str>) -> KunaResult<crate::fspec::ModelBinding> {
        self.model_context.borrow().as_ref().ok_or_else(|| KunaError::lowlevel("Type factory model context is not initialized"))?.bind(name)
    }
    fn model_binding_for(&self, model: Rc<crate::fspec::ProtoModel>) -> KunaResult<crate::fspec::ModelBinding> {
        self.model_context.borrow().as_ref().ok_or_else(|| KunaError::lowlevel("Type factory model context is not initialized"))?.bind_model(model)
    }
    fn get_abi_view(&self, id: TypeId) -> Option<Rc<crate::fspec::AbiView>> { self.abi_cache.borrow().get(&id).cloned() }
    fn cache_abi_view(&self, id: TypeId, view: Rc<crate::fspec::AbiView>) -> KunaResult<()> {
        let root = self.graph.root(id)?;
        if view.root().id() != id { return Err(KunaError::lowlevel("Callable ABI cache identity mismatch")); }
        if !root.read().abi_ready(id)? { return Err(KunaError::lowlevel("Callable ABI layout is not ready")); }
        self.abi_cache.try_borrow_mut().map_err(|_| KunaError::lowlevel("Datatype ABI cache busy"))?.insert(id, view);
        Ok(())
    }
    fn kuna_variant_types(&self) -> Vec<TypeRoot> { self.graph.variant_types() }

    fn get_size_of_int(&self) -> int4 {
        self.size_of_int.get()
    }
    fn get_size_of_long(&self) -> int4 {
        self.size_of_long.get()
    }
    fn get_size_of_char(&self) -> int4 {
        self.size_of_char.get()
    }
    fn get_size_of_wchar(&self) -> int4 {
        self.size_of_wchar.get()
    }
    fn get_size_of_pointer(&self) -> int4 {
        self.size_of_pointer.get()
    }
    fn get_size_of_alt_pointer(&self) -> int4 {
        self.size_of_alt_pointer.get()
    }
    fn get_size_of_short(&self) -> int4 {
        self.size_of_short.get()
    }
    fn get_size_of_long_long(&self) -> int4 {
        self.size_of_long_long.get()
    }
    fn get_size_of_float(&self) -> int4 {
        self.size_of_float.get()
    }
    fn get_size_of_double(&self) -> int4 {
        self.size_of_double.get()
    }
    fn get_size_of_long_double(&self) -> int4 {
        self.size_of_long_double.get()
    }
    fn get_alignment(&self, size: uint4) -> KunaResult<int4> {
        self.alignment(size)
    }
    fn get_primitive_align_size(&self, size: uint4) -> KunaResult<int4> {
        self.primitive_align_size(size)
    }

    fn get_type_void(&self) -> KunaResult<TypeRoot> {
        self.get_type_void_impl()
    }
    fn get_base_no_char(&self, s: int4, m: type_metatype) -> KunaResult<TypeRoot> {
        self.get_base_no_char_impl(s, m)
    }
    fn get_base(&self, s: int4, m: type_metatype) -> KunaResult<TypeRoot> {
        self.get_base_impl(s, m)
    }
    fn get_base_named(&self, s: int4, m: type_metatype, n: &str) -> KunaResult<TypeRoot> {
        self.get_base_named_impl(s, m, n)
    }
    fn get_type_char(&self, s: int4) -> KunaResult<TypeRoot> {
        self.get_type_char_sized(s)
    }
    fn get_type_code(&self) -> KunaResult<TypeRoot> {
        self.get_type_code_impl()
    }

    fn get_type_code_proto(
        &self,
        proto: &crate::fspec::LogicalCallable,
    ) -> KunaResult<TypeRoot> {
        self.make_type_code_proto(proto)
    }

    fn get_type_pointer_strip_array(
        &self,
        s: int4,
        pt: TypeRoot,
        ws: uint4,
    ) -> KunaResult<TypeRoot> {
        self.get_type_pointer_strip_array_impl(s, pt, ws, None)
    }
    fn get_type_pointer(&self, s: int4, pt: TypeRoot, ws: uint4) -> KunaResult<TypeRoot> {
        self.get_type_pointer_impl(s, pt, ws, None)
    }
    fn get_type_pointer_named(
        &self,
        s: int4,
        pt: TypeRoot,
        ws: uint4,
        n: &str,
    ) -> KunaResult<TypeRoot> {
        self.get_type_pointer_named_impl(s, pt, ws, n)
    }
    fn resize_pointer(&self, ptr: TypeRoot, new_size: int4) -> KunaResult<TypeRoot> {
        self.resize_pointer_impl(&ptr, new_size)
    }
    fn get_type_pointer_rel(
        &self,
        parent_ptr: TypeRoot,
        ptr_to: TypeRoot,
        off: int4,
    ) -> KunaResult<TypeRoot> {
        self.get_type_pointer_rel_impl(parent_ptr, ptr_to, off)
    }
    fn get_type_pointer_rel_full(
        &self,
        sz: int4,
        parent: TypeRoot,
        ptr_to: TypeRoot,
        ws: int4,
        off: int4,
        nm: &str,
    ) -> KunaResult<TypeRoot> {
        self.get_type_pointer_rel_full_impl(sz, parent, ptr_to, ws, off, nm)
    }
    fn get_type_pointer_with_space(
        &self,
        size: int4,
        ptr_to: TypeRoot,
        wordsize: uint4,
        spc: Rc<AddrSpace>,
        nm: &str,
    ) -> KunaResult<TypeRoot> {
        self.get_type_pointer_with_space_impl(size, ptr_to, wordsize, spc, nm)
    }

    fn get_type_array(&self, as_: int4, ao: TypeRoot) -> KunaResult<TypeRoot> {
        self.get_type_array_impl(as_, ao)
    }
    fn get_type_struct(&self, n: &str) -> KunaResult<TypeRoot> {
        self.get_type_struct_impl(n)
    }
    fn get_type_partial_struct(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot> {
        self.get_type_partial_struct_impl(contain, off, sz)
    }
    fn get_type_union(&self, n: &str) -> KunaResult<TypeRoot> {
        self.get_type_union_impl(n)
    }
    fn get_type_partial_union(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot> {
        self.get_type_partial_union_impl(contain, off, sz)
    }
    fn get_type_partial_enum(
        &self,
        contain: TypeRoot,
        off: int4,
        sz: int4,
    ) -> KunaResult<TypeRoot> {
        self.get_type_partial_enum_impl(contain, off, sz)
    }
    fn get_type_enum(&self, n: &str) -> KunaResult<TypeRoot> {
        self.get_type_enum_impl(n)
    }
    fn get_type_enum_sized(&self, n: &str, s: int4, m: type_metatype) -> KunaResult<TypeRoot> {
        self.get_type_enum_sized_impl(n, s, m)
    }
    fn get_type_spacebase(&self, id: Rc<AddrSpace>, addr: &Address) -> KunaResult<TypeRoot> {
        self.get_type_spacebase_impl(id, addr)
    }

    fn resize_integer(&self, ct: TypeRoot, new_size: int4) -> KunaResult<TypeRoot> {
        self.resize_integer_impl(ct, new_size)
    }
    fn get_exact_piece(
        &self,
        ct: TypeRoot,
        offset: int4,
        size: int4,
    ) -> KunaResult<Option<TypeRoot>> {
        self.get_exact_piece_impl(ct, offset, size)
    }

    fn find_by_name(&self, n: &str) -> KunaResult<Option<TypeRoot>> {
        Ok(self.find_by_name_impl(n))
    }
    fn concretize(&self, ct: TypeRoot) -> KunaResult<TypeRoot> {
        self.concretize_impl(ct)
    }

    fn is_big_endian(&self) -> bool {
        self.is_big_endian_impl()
    }
    fn set_name(&self, ct: &TypeRoot, n: &str) -> KunaResult<TypeRoot> {
        self.set_name_impl(ct, n)
    }
    fn set_display_format(&self, ct: &TypeRoot, format: uint4) -> KunaResult<TypeRoot> {
        self.set_display_format_impl(ct, format)
    }
    fn assign_raw_fields_struct(
        &self,
        ct: &TypeRoot,
        fd: Vec<TypeField>,
        bit: Vec<TypeBitField>,
    ) -> KunaResult<TypeRoot> {
        self.assign_raw_fields_struct_impl(ct, fd, bit)
    }
    fn assign_raw_fields_union(
        &self,
        ct: &TypeRoot,
        fd: Vec<TypeField>,
    ) -> KunaResult<TypeRoot> {
        self.assign_raw_fields_union_impl(ct, fd)
    }
    fn set_fields_struct_raw(
        &self,
        ct: &TypeRoot,
        fd: Vec<TypeField>,
        bit: Vec<TypeBitField>,
        size: int4,
        align: int4,
        extra_flags: uint4,
    ) -> KunaResult<TypeRoot> {
        self.set_fields_struct(ct, fd, bit, size, align, extra_flags)
    }
    fn set_fields_union_raw(
        &self,
        ct: &TypeRoot,
        fd: Vec<TypeField>,
        size: int4,
        align: int4,
    ) -> KunaResult<TypeRoot> {
        self.set_fields_union(ct, fd, size, align, 0)
    }
    fn set_enum_values(
        &self,
        ct: &TypeRoot,
        nmap: std::collections::BTreeMap<u64, String>,
    ) -> KunaResult<TypeRoot> {
        self.set_enum_values_impl(ct, nmap)
    }
    fn get_typedef(
        &self,
        ct: &TypeRoot,
        name: &str,
        id: uint8,
        format: uint4,
    ) -> KunaResult<TypeRoot> {
        self.get_typedef_impl(ct, name, id, format)
    }
    fn destroy_type(&self, ct: &TypeRoot) -> KunaResult<()> {
        self.destroy_type_impl(ct)
    }
    fn kuna_record_variant_layout(&self, owner: &TypeRoot, layout: crate::kuna_dwarfvariants::VariantLayout) -> KunaResult<()> {
        self.graph.record_variant(owner, layout)
    }


}

#[cfg(test)]
mod tests {
    use crate::prettyprint::ids::ELEM_TYPE;

use super::*;
    use type_metatype::*;

    fn factory() -> TypeFactoryImpl {
        let factory = TypeFactoryImpl::new();
        factory.set_default_alignment_map();
        factory.set_max_basetype_size(8);
        factory
    }

    fn structure(factory: &TypeFactoryImpl, name: &str, size: int4, align: int4, fields: Vec<TypeField>) -> TypeRoot {
        let mut draft = Datatype::new_with_align(size, align, TYPE_STRUCT);
        draft.name = name.to_owned();
        draft.display_name = name.to_owned();
        if !name.is_empty() { draft.id = Datatype::hash_name(name); }
        draft.kind = DatatypeKind::Struct { field: fields, bitfield: Vec::new() };
        factory.intern(draft).unwrap()
    }

    fn flags_enum(factory: &TypeFactoryImpl) -> TypeRoot {
        let root = factory.get_type_enum_sized("flags", 8, TYPE_ENUM_UINT).unwrap();
        factory.set_enum_values(&root, BTreeMap::new()).unwrap()
    }

    fn identity_factory() -> TypeFactoryImpl {
        let factory = factory();
        let manager = Rc::new(kuna_base::space::AddrSpaceManager::new());
        factory.set_proto_context(Some(Rc::new(crate::fspec::ProtoModel::new(&manager))), manager).unwrap();
        factory
    }

    fn decode_identity(factory: &TypeFactoryImpl, xml: &str) -> KunaResult<TypeRoot> {
        use kuna_base::marshal::*;
        let manager = kuna_base::space::AddrSpaceManager::new();
        let mut registry = IdRegistry::new();
        for attribute in [&ATTRIB_NAME, &ATTRIB_ID, &ATTRIB_SIZE, &ATTRIB_METATYPE, &super::ATTRIB_VARLENGTH, &super::ATTRIB_CORE] {
            registry.register_attribute(attribute);
        }
        for element in [&crate::prettyprint::ids::ELEM_TYPE, &super::ELEM_TYPEREF, &super::ELEM_DEF,
            &ELEM_VOID, &kuna_base::address::ELEM_ADDR, &crate::remote_provider::ELEM_PROTOTYPE,
            &crate::remote_provider::ELEM_RETURNSYM] {
            registry.register_element(element);
        }
        let mut decoder = XmlDecode::new(&manager, &registry);
        decoder.ingest_stream(xml.as_bytes())?;
        factory.decode_type(&mut decoder)
    }

    fn decode_host_identity(factory: &TypeFactoryImpl, xml: &str) -> KunaResult<TypeRoot> {
        use kuna_base::marshal::*;
        let manager = kuna_base::space::AddrSpaceManager::new();
        let mut registry = IdRegistry::new();
        register_type_wire_ids(&mut registry);
        for attribute in [&ATTRIB_NAME, &ATTRIB_ID, &ATTRIB_SIZE, &ATTRIB_METATYPE, &ATTRIB_OFFSET, &ATTRIB_CONTENT] {
            registry.register_attribute(attribute);
        }
        for element in [&crate::prettyprint::ids::ELEM_TYPE, &crate::prettyprint::ids::ELEM_FIELD,
            &ELEM_OFF, &ELEM_VOID, &kuna_base::address::ELEM_ADDR, &crate::remote_provider::ELEM_PROTOTYPE,
            &crate::remote_provider::ELEM_RETURNSYM] {
            registry.register_element(element);
        }
        let mut decoder = XmlDecode::new(&manager, &registry);
        decoder.ingest_stream(xml.as_bytes())?;
        factory.decode_host_type(&mut decoder)
    }

    fn source_marker(size: int4) -> String {
        format!(r#"kuna_source_program="71" kuna_source_revision="9" kuna_source_kind="program" kuna_source_size="{size}" kuna_source_scope="" kuna_source_binding="""#)
    }

    fn pending_source_child_wire() -> String {
        format!(r#"<type name="ReceiptChild" id="701" size="8" metatype="struct" {}><field name="tail" offset="0" id="4"><typeref name="ReceiptTail" id="702"/></field></type>"#, source_marker(8))
    }

    fn source_callback_wire() -> String {
        format!(r#"<type name="ReceiptCallback" id="703" size="1" metatype="code" {}><prototype><returnsym><addr/><typeref name="ReceiptChild" id="701" {}/></returnsym></prototype></type>"#, source_marker(1), source_marker(8))
    }

    #[test]
    fn host_source_same_size_child_correction_invalidates_callable_and_inline_ancestors() {
        let factory = identity_factory();
        factory.graph.reserve("ReceiptTail", 702, TYPE_STRUCT, false).unwrap();
        let child = decode_host_identity(&factory, &pending_source_child_wire()).unwrap();
        assert_eq!(factory.state(&child).unwrap(), TypeState::Pending);
        let callback = decode_host_identity(&factory, &source_callback_wire()).unwrap();
        let outer_wire = format!(r#"<type name="ReceiptOwner" id="704" size="16" metatype="struct" {}><field name="callbacks" offset="0" id="8"><type name="" size="16" metatype="array" arraysize="2"><type name="" size="8" metatype="ptr"><typeref name="ReceiptCallback" id="703" size="1" {}/></type></type></field></type>"#, source_marker(16), source_marker(1));
        let owner = decode_host_identity(&factory, &outer_wire).unwrap();
        for root in [&child, &callback, &owner] {
            assert_eq!(root.read().host_source(root.id()).unwrap().unwrap().program, 71);
        }
        let correction = child.read().definition(child.id()).unwrap().clone();
        factory.correct_pending(&child, correction).unwrap();
        assert_eq!(child.get_size(), 8);
        for root in [&child, &callback, &owner] {
            assert!(root.read().host_source(root.id()).is_err());
        }
        let reference = format!(r#"<typeref name="ReceiptChild" id="701" {}/>"#, source_marker(8));
        assert!(decode_host_identity(&factory, &reference).is_err());
        assert!(child.read().host_source(child.id()).is_err());
        let rebound = decode_host_identity(&factory, &pending_source_child_wire()).unwrap();
        assert_eq!(rebound, child);
        assert_eq!(child.read().host_source(child.id()).unwrap().unwrap().id, 701);
        assert!(callback.read().host_source(callback.id()).is_err());
        decode_host_identity(&factory, &source_callback_wire()).unwrap();
        assert_eq!(callback.read().host_source(callback.id()).unwrap().unwrap().id, 703);
        assert!(owner.read().host_source(owner.id()).is_err());
        decode_host_identity(&factory, &outer_wire).unwrap();
        assert_eq!(owner.read().host_source(owner.id()).unwrap().unwrap().id, 704);
        let native = structure(&factory, "NativeOnly", 8, 8, Vec::new());
        assert!(native.read().host_source(native.id()).unwrap().is_none());
    }

    #[test]
    fn host_source_batch_rejects_earlier_callback_after_later_child_correction() {
        let factory = identity_factory();
        factory.graph.reserve("ReceiptTail", 702, TYPE_STRUCT, false).unwrap();
        let result = factory.with_host_decode(|| {
            let child = decode_host_identity(&factory, &pending_source_child_wire())?;
            let callback = decode_host_identity(&factory, &source_callback_wire())?;
            let correction = child.read().definition(child.id())?.clone();
            factory.correct_pending(&child, correction)?;
            // A later fresh full decode can renew Child itself, not the earlier
            // callback's already-completed source definition or its epoch.
            decode_host_identity(&factory, &pending_source_child_wire())?;
            Ok(callback)
        });
        assert!(result.is_err());
        let callback = factory.graph.find_source("ReceiptCallback", 703, false).unwrap().unwrap();
        assert!(callback.read().host_source(callback.id()).unwrap().is_none());
        // Failure cannot leave a queued receipt capable of authenticating a ref.
        let reference = format!(r#"<typeref name="ReceiptCallback" id="703" size="1" {}/>"#, source_marker(1));
        assert!(decode_host_identity(&factory, &reference).is_err());
    }

    #[test]
    fn host_source_relative_parent_correction_invalidates_unchanged_pointee() {
        let factory = identity_factory();
        factory.graph.reserve("ReceiptTail", 702, TYPE_STRUCT, false).unwrap();
        let parent = decode_host_identity(&factory, &pending_source_child_wire()).unwrap();
        let wire = format!(r#"<type name="ReceiptRelative" id="705" size="8" metatype="ptrrel" {}><type name="" size="1" metatype="uint"/><typeref name="ReceiptChild" id="701" {}/><off>1</off></type>"#, source_marker(8), source_marker(8));
        let relative = decode_host_identity(&factory, &wire).unwrap();
        let pointee = relative.get_ptr_to().unwrap();
        assert_eq!(relative.get_rel_parent(), Some(parent.clone()));
        assert_eq!(relative.read().host_source(relative.id()).unwrap().unwrap().id, 705);
        let correction = parent.read().definition(parent.id()).unwrap().clone();
        factory.correct_pending(&parent, correction).unwrap();
        assert_eq!(relative.get_ptr_to(), Some(pointee));
        assert!(relative.read().host_source(relative.id()).is_err());
        decode_host_identity(&factory, &pending_source_child_wire()).unwrap();
        assert!(relative.read().host_source(relative.id()).is_err());
        assert_eq!(decode_host_identity(&factory, &wire).unwrap(), relative);
        assert_eq!(relative.read().host_source(relative.id()).unwrap().unwrap().id, 705);
    }

    fn callback_wire(size: int4, explicit: bool) -> String {
        format!("<type name=\"Callback\" id=\"0x600000000000000\" size=\"{size}\" metatype=\"code\"{}><prototype><returnsym><addr/><void/></returnsym></prototype></type>",
            if explicit { " varlength=\"true\"" } else { "" })
    }

    fn pointer_spaces() -> kuna_base::space::AddrSpaceManager {
        use kuna_base::space::*;
        let mut manager = AddrSpaceManager::new();
        manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        for (index, name) in [(1, "INTMEM"), (2, "SFR")] {
            manager.insert_space(Rc::new(AddrSpace::new(
                spacetype::IPTR_PROCESSOR, name, true, 1, 1, index, 0, 0, 0,
            ))).unwrap();
        }
        manager
    }

    fn decode_pointer_wire(
        factory: &TypeFactoryImpl,
        manager: &kuna_base::space::AddrSpaceManager,
        space: &str,
        relative: bool,
    ) -> KunaResult<TypeRoot> {
        use kuna_base::marshal::*;
        let mut registry = IdRegistry::new();
        for attribute in [&ATTRIB_NAME, &ATTRIB_SIZE, &ATTRIB_METATYPE, &ATTRIB_SPACE,
            &ATTRIB_CONTENT, &super::ATTRIB_ARRAYSIZE] {
            registry.register_attribute(attribute);
        }
        for element in [&ELEM_TYPE, &ELEM_OFF] {
            registry.register_element(element);
        }
        let extra = if relative {
            r#"<type name="" size="4" metatype="array" arraysize="4"><type name="" size="1" metatype="uint"/></type><off>1</off>"#
        } else { "" };
        let xml = format!(r#"<type name="" size="1" metatype="{}" space="{space}"><type name="" size="1" metatype="uint"/>{extra}</type>"#,
            if relative { "ptrrel" } else { "ptr" });
        let mut decoder = XmlDecode::new(manager, &registry);
        decoder.ingest_stream(xml.as_bytes())?;
        factory.decode_type(&mut decoder)
    }

    #[test]
    fn wire_pointer_banks_remain_distinct_through_interning_and_encoding() {
        use kuna_base::marshal::{Decoder, PackedDecode, PackedEncode};
        let factory = factory();
        let manager = pointer_spaces();
        for relative in [false, true] {
            let ram = decode_pointer_wire(&factory, &manager, "INTMEM", relative).unwrap();
            let sfr = decode_pointer_wire(&factory, &manager, "SFR", relative).unwrap();
            assert_ne!(ram, sfr);
            assert_ne!(ram.compare(&sfr, 10).unwrap(), 0);
            assert_ne!(ram.compare_dependency(&sfr).unwrap(), 0);
            for (pointer, bank) in [(ram, "INTMEM"), (sfr, "SFR")] {
                assert_eq!(pointer.get_pointer_space().unwrap().get_name(), bank);
                assert_eq!((pointer.get_size(), pointer.get_word_size()), (1, Some(1)));
                let mut bytes = Vec::new();
                pointer.encode(&mut PackedEncode::new(&mut bytes)).unwrap();
                let fresh = TypeFactoryImpl::new();
                let mut decoder = PackedDecode::new(&manager);
                decoder.ingest_stream(&bytes).unwrap();
                let restored = fresh.decode_type(&mut decoder).unwrap();
                assert_eq!(restored.get_pointer_space().unwrap().get_name(), bank);
                assert_eq!(restored.is_pointer_rel(), relative);
            }
        }
        assert!(decode_pointer_wire(&factory, &manager, "missing", false).is_err());
    }

    #[test]
    fn qualified_pointer_derivations_keep_the_address_bank() {
        let factory = factory();
        let manager = pointer_spaces();
        let pointer = decode_pointer_wire(&factory, &manager, "SFR", false).unwrap();
        let alias = factory.get_typedef(&pointer, "Port", 0x1234, 0).unwrap();
        factory.size_of_pointer.set(1);
        factory.size_of_alt_pointer.set(2);
        let wide = factory.resize_pointer(alias, 2).unwrap();
        let truncated = {
            let view = wide.read();
            match &view.get(wide.id()).unwrap().kind {
                DatatypeKind::Pointer { truncate: Some(id), .. } => factory.root(*id).unwrap(),
                _ => panic!("alternate pointer must retain its narrow form"),
            }
        };
        let byte = pointer.get_ptr_to().unwrap();
        let array = factory.get_type_array(4, byte.clone()).unwrap();
        let record = structure(&factory, "Ports", 4, 1, vec![TypeField::new(0, 0, "ports", array.id())]);
        let bank = pointer.get_pointer_space().unwrap();
        let record_pointer = factory.get_type_pointer_with_space(1, record, 1, bank.clone(), "").unwrap();
        let field = factory.down_chain(&record_pointer, 0, false).unwrap().0.unwrap();
        let array_pointer = factory.get_type_pointer_with_space(1, array, 1, bank.clone(), "").unwrap();
        let element = factory.down_chain(&array_pointer, 2, false).unwrap().0.unwrap();
        let enumeration = flags_enum(&factory);
        let enum_pointer = factory.get_type_pointer_with_space(1, enumeration, 1, bank, "").unwrap();
        let enum_byte = factory.down_chain(&enum_pointer, 0, false).unwrap().0.unwrap();
        let relative = factory.get_type_pointer_rel(record_pointer, byte, 1).unwrap();
        let stripped = relative.get_stripped().unwrap();
        let parent = factory.down_chain(&relative, -1, false).unwrap().0.unwrap();
        for derived in [wide, truncated, field, element, enum_byte, relative, stripped, parent] {
            assert_eq!(derived.get_pointer_space().unwrap().get_name(), "SFR");
        }
    }

    fn encoded_identity(root: &TypeRoot) -> (u32, Option<uint8>, Option<int4>) {
        use kuna_base::marshal::*;
        let mut wire = Vec::new();
        root.encode_ref(&mut PackedEncode::new(&mut wire)).unwrap();
        let manager = kuna_base::space::AddrSpaceManager::new();
        let mut decoder = PackedDecode::new(&manager);
        decoder.ingest_stream(&wire).unwrap();
        let element = decoder.open_element().unwrap();
        let (mut id, mut size) = (None, None);
        loop {
            let attribute = decoder.get_next_attribute_id().unwrap();
            if attribute == 0 { break; }
            if attribute == ATTRIB_ID.get_id() { id = Some(decoder.read_unsigned_integer().unwrap()); }
            else if attribute == ATTRIB_SIZE.get_id() { size = Some(decoder.read_signed_integer().unwrap() as int4); }
        }
        (element, id, size)
    }

    #[test]
    fn callback_wire_identity_is_independent_of_implicit_variable_length() {
        let factory = identity_factory();
        let implicit = decode_identity(&factory, &callback_wire(1, false)).unwrap();
        let explicit = decode_identity(&factory, &callback_wire(1, true)).unwrap();
        assert_eq!(implicit.id(), explicit.id());
        assert_eq!(encoded_identity(&implicit), (ELEM_TYPEREF.get_id(), Some(0x600000000000000), Some(1)));
        let reference = decode_identity(&factory, "<typeref name=\"Callback\" id=\"0x600000000000000\" size=\"1\"/>").unwrap();
        assert_eq!(reference.id(), implicit.id());
        assert!(decode_identity(&factory, "<typeref name=\"Callback\" id=\"0x600000000000000\"/>").is_err());
        let fixed = decode_identity(&factory, "<type name=\"Callback\" id=\"0x600000000000000\" size=\"1\" metatype=\"code\"/>").unwrap();
        assert_ne!(fixed.id(), implicit.id());
        assert_eq!(encoded_identity(&fixed), (ELEM_TYPEREF.get_id(), Some(0x600000000000000), None));
        assert_eq!(decode_identity(&factory, "<typeref name=\"Callback\" id=\"0x600000000000000\"/>").unwrap().id(), fixed.id());
        let anonymous = decode_identity(&factory, "<type name=\"\" size=\"1\" metatype=\"code\"><prototype><returnsym><addr/><void/></returnsym></prototype></type>").unwrap();
        assert_eq!(encoded_identity(&anonymous), (crate::prettyprint::ids::ELEM_TYPE.get_id(), None, Some(1)));
    }

    #[test]
    fn full_alias_headers_select_exact_instances_before_bodies() {
        let factory = identity_factory();
        let definition = |size| format!("<def name=\"Outer\" id=\"0x700000000000001\"><def name=\"Alias\" id=\"0x700000000000000\">{}</def></def>", callback_wire(size, false));
        let one = decode_identity(&factory, &definition(1)).unwrap();
        let two = decode_identity(&factory, &definition(2)).unwrap();
        assert_ne!(one.id(), two.id());
        assert_eq!(decode_identity(&factory, &definition(1)).unwrap().id(), one.id());
        assert_eq!(decode_identity(&factory, &definition(2)).unwrap().id(), two.id());
        assert_eq!(encoded_identity(&one), (ELEM_TYPEREF.get_id(), Some(0x700000000000001), Some(1)));
        assert_eq!(encoded_identity(&two), (ELEM_TYPEREF.get_id(), Some(0x700000000000001), Some(2)));
        assert_eq!(factory.find_by_instance("Outer", 0x700000000000001, Some(1)).unwrap().id(), one.id());
        assert_eq!(factory.find_by_instance("Outer", 0x700000000000001, Some(2)).unwrap().id(), two.id());
        assert!(factory.find_by_source_id("Outer", 0x700000000000001).is_err());
        let wrong = "<def name=\"Outer\" id=\"0x700000000000001\"><type name=\"Other\" id=\"0x600000000000001\" size=\"1\" metatype=\"code\" varlength=\"true\"/></def>";
        assert!(decode_identity(&factory, wrong).is_err());
        let target = one.get_typedef().unwrap();
        assert_eq!(target.read().get(target.id()).unwrap().get_name(), "Alias");
    }

    #[test]
    fn delayed_code_instance_updates_completed_alias_and_survives_flush() {
        let factory = identity_factory();
        let code = factory.reserve("Callback", 0x600000000000000, TYPE_CODE).unwrap();
        let alias = factory.get_typedef(&code, "Alias", 0x700000000000000, 0).unwrap();
        let alias_id = alias.id();
        assert_eq!((alias.get_size(), alias.is_variable_length()), (0, false));
        assert_eq!(factory.state(&alias).unwrap(), TypeState::Complete);
        let completed = decode_identity(&factory, &callback_wire(1, false)).unwrap();
        assert_eq!(completed.id(), code.id());
        assert_eq!(alias.id(), alias_id);
        assert_eq!((alias.get_size(), alias.is_variable_length()), (1, true));
        assert_eq!(decode_identity(&factory, "<typeref name=\"Alias\" id=\"0x700000000000000\" size=\"1\"/>").unwrap().id(), alias_id);
        assert_eq!(encoded_identity(&alias), (ELEM_TYPEREF.get_id(), Some(0x700000000000000), Some(1)));
        factory.clear_noncore().unwrap();
        assert_eq!(encoded_identity(&alias), (ELEM_TYPEREF.get_id(), Some(0x700000000000000), Some(1)));
        let reloaded = decode_identity(&factory, &callback_wire(1, false)).unwrap();
        assert_ne!(reloaded.id(), code.id());
        assert_eq!(reloaded.get_unsized_id().unwrap(), code.get_unsized_id().unwrap());
    }

    #[test]
    fn transitive_instance_collision_rolls_back_and_retry_keeps_roots() {
        let factory = identity_factory();
        let first = factory.reserve("First", 101, TYPE_CODE).unwrap();
        let second = factory.reserve("Second", 102, TYPE_CODE).unwrap();
        let alias1 = factory.get_typedef(&first, "Shared", 200, 0).unwrap();
        let alias2 = factory.get_typedef(&second, "Shared", 200, 0).unwrap();
        assert_ne!(alias1.id(), alias2.id());
        let complete = |root: &TypeRoot, size| {
            let mut draft = Datatype::new_with_align(size, 1, TYPE_CODE);
            draft.name = root.read().get(root.id()).unwrap().get_name().to_owned(); draft.display_name = draft.name.clone(); draft.id = root.get_id();
            draft.kind = DatatypeKind::Code { proto: None }; draft.flags |= flags::variable_length;
            factory.complete(root, draft)
        };
        complete(&first, 1).unwrap();
        assert!(complete(&second, 1).is_err());
        assert_eq!((alias2.get_size(), alias2.is_variable_length()), (0, false));
        assert_eq!(factory.find_by_instance("Shared", 200, Some(1)).unwrap().id(), alias1.id());
        complete(&second, 2).unwrap();
        assert_eq!(factory.find_by_instance("Shared", 200, Some(2)).unwrap().id(), alias2.id());
        assert_eq!(encoded_identity(&alias2), (ELEM_TYPEREF.get_id(), Some(200), Some(2)));
    }

    #[test]
    fn generic_struct_shell_adopts_sized_header_without_changing_alias_identity() {
        let factory = identity_factory();
        let shell = factory.reserve("Sized", 301, TYPE_STRUCT).unwrap();
        let alias = factory.get_typedef(&shell, "SizedAlias", 302, 0).unwrap();
        let completed = decode_identity(&factory, "<type name=\"Sized\" id=\"301\" size=\"4\" metatype=\"struct\" varlength=\"true\"/>").unwrap();
        assert_eq!(completed.id(), shell.id());
        assert_eq!((alias.get_size(), alias.is_variable_length()), (4, true));
        assert_eq!(factory.find_by_instance("SizedAlias", 302, Some(4)).unwrap().id(), alias.id());
    }

    #[test]
    fn unconfigured_factory_constructs_primitives_and_oversized_unknown_arrays() {
        let factory = TypeFactoryImpl::new();
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        assert_eq!((integer.get_metatype(), integer.get_size()), (TYPE_INT, 4));
        let limit = factory.get_base(16, TYPE_INT).unwrap();
        assert_eq!((limit.get_metatype(), limit.get_size()), (TYPE_INT, 16));
        let oversized = factory.get_base(17, TYPE_INT).unwrap();
        assert_eq!((oversized.get_metatype(), oversized.get_size()), (TYPE_ARRAY, 17));
        let element = oversized.get_array_base().unwrap();
        assert_eq!((element.get_metatype(), element.get_size()), (TYPE_UNKNOWN, 1));
        assert_eq!(element, factory.get_base(1, TYPE_UNKNOWN).unwrap());
    }

    #[test]
    fn wire_encode_roundtrips_through_decode_type() {
        use kuna_base::marshal::{Decoder, PackedDecode, PackedEncode};
        let factory = factory();
        factory.set_core_type("int", 4, TYPE_INT, false).unwrap();
        factory.set_core_type("undefined", 1, TYPE_UNKNOWN, false).unwrap();
        factory.cache_core_types().unwrap();
        let manager = kuna_base::space::AddrSpaceManager::new();
        let roundtrip = |root: &TypeRoot, full: bool| {
            let mut bytes = Vec::new();
            let mut encoder = PackedEncode::new(&mut bytes);
            if full { root.encode(&mut encoder).unwrap(); }
            else { root.encode_ref(&mut encoder).unwrap(); }
            let mut decoder = PackedDecode::new(&manager);
            decoder.ingest_stream(&bytes).unwrap();
            factory.decode_type(&mut decoder).unwrap()
        };
        let integer = factory.find_by_name("int").unwrap().unwrap();
        assert_ne!(integer.get_id(), 0);
        assert_eq!(roundtrip(&integer, false), integer);
        let pointer = factory.get_type_pointer(8, integer.clone(), 1).unwrap();
        assert_eq!(pointer.get_id(), 0);
        assert_eq!(roundtrip(&pointer, false), pointer);
        let array = factory.get_type_array(5, integer).unwrap();
        assert_eq!(roundtrip(&array, true), array);
    }

    #[test]
    fn wire_bitfield_container_preserves_cross_byte_range() {
        use kuna_base::marshal::{Decoder, Encoder, PackedDecode, PackedEncode};
        for big_endian in [false, true] {
            for size in [4, 1] {
                let factory = factory();
                factory.set_truncate_big_endian(big_endian);
                let manager = kuna_base::space::AddrSpaceManager::new();
                let mut bytes = Vec::new();
                let mut enc = PackedEncode::new(&mut bytes);
                enc.open_element(&ELEM_TYPE);
                enc.write_string(&kuna_base::marshal::ATTRIB_NAME, b"Bits");
                enc.write_string(&kuna_base::marshal::ATTRIB_METATYPE, b"struct");
                enc.write_signed_integer(&kuna_base::marshal::ATTRIB_SIZE, size);
                let element = crate::prettyprint::ids::ELEM_BITFIELD;
                enc.open_element(&element);
                enc.write_string(&kuna_base::marshal::ATTRIB_NAME, b"middle");
                enc.write_signed_integer(&kuna_base::marshal::ATTRIB_OFFSET, 0);
                enc.write_signed_integer(&kuna_base::address::ATTRIB_FIRST, 3);
                enc.write_signed_integer(&kuna_base::marshal::ATTRIB_SIZE, 8);
                enc.open_element(&ELEM_TYPE);
                enc.write_string(&kuna_base::marshal::ATTRIB_METATYPE, b"uint");
                enc.write_signed_integer(&kuna_base::marshal::ATTRIB_SIZE, 4);
                enc.close_element(&ELEM_TYPE);
                enc.close_element(&element);
                enc.close_element(&ELEM_TYPE);
                let mut dec = PackedDecode::new(&manager);
                dec.ingest_stream(&bytes).unwrap();
                let decoded = factory.decode_type(&mut dec);
                if size == 1 {
                    assert!(decoded.is_err(), "cross-byte field exceeds its structure");
                    continue;
                }
                let root = decoded.unwrap();
                let view = root.read();
                let DatatypeKind::Struct { bitfield, .. } = &view.definition(root.id()).unwrap().kind
                    else { panic!("decoded bitfield container is not a structure") };
                let bits = bitfield[0].bits();
                assert_eq!((bits.byte_offset, bits.byte_size, bits.least_sig_bit, bits.num_bits), (0, 2, 3, 8));
                let container = crate::bitfield::BitRange::new(0, 4, 0, 32, big_endian);
                assert_eq!(container.translate_lsb(&bits), if big_endian { 19 } else { 3 });
            }
        }
    }

    #[test]
    fn decode_integer_format_vocabulary() {
        for (code, spelling) in [(1, "hex"), (2, "dec"), (3, "oct"), (4, "bin"), (5, "char")] {
            assert_eq!(Datatype::decode_integer_format(code).unwrap(), spelling);
            assert_eq!(wire_integer_format(spelling), code);
        }
        assert!(Datatype::decode_integer_format(0).is_err());
        assert!(Datatype::decode_integer_format(6).is_err());
    }

    #[test]
    fn factory_negative_size_is_an_error_not_a_panic() {
        let factory = factory();
        factory.set_core_type("undefined", 1, TYPE_UNKNOWN, false).unwrap();
        factory.set_core_type("char", 1, TYPE_INT, true).unwrap();
        factory.cache_core_types().unwrap();
        for size in [-1, -16, i32::MIN] {
            assert!(factory.get_base(size, TYPE_UNKNOWN).is_err());
            assert!(factory.get_base_no_char(size, TYPE_INT).is_err());
            assert!(factory.get_type_char(size).is_err());
        }
        assert_eq!(factory.get_base(4, TYPE_UNKNOWN).unwrap().get_size(), 4);
        assert!(factory.get_type_char(1).unwrap().is_ascii());
    }

    #[test]
    fn factory_find_add_dedup_identity() {
        let factory = factory();
        let first = factory.get_base(4, TYPE_INT).unwrap();
        let second = factory.get_base(4, TYPE_INT).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, factory.get_base(8, TYPE_INT).unwrap());
        let pointer = factory.get_type_pointer(8, first.clone(), 1).unwrap();
        assert_eq!(pointer, factory.get_type_pointer(8, second, 1).unwrap());
        assert_eq!(pointer.get_ptr_to(), Some(first));
    }

    #[test]
    fn factory_core_type_cache() {
        let factory = factory();
        for (name, size, meta, character) in [
            ("void", 0, TYPE_VOID, false), ("byte", 1, TYPE_UINT, false),
            ("sbyte", 1, TYPE_INT, false), ("char", 1, TYPE_INT, true),
            ("undefined", 1, TYPE_UNKNOWN, false), ("int", 4, TYPE_INT, false),
            ("double", 8, TYPE_FLOAT, false),
        ] { factory.set_core_type(name, size, meta, character).unwrap(); }
        factory.cache_core_types().unwrap();
        assert!(factory.get_base(1, TYPE_INT).unwrap().is_ascii());
        assert!(!factory.get_base_no_char(1, TYPE_INT).unwrap().is_ascii());
        assert!(factory.get_type_char(1).unwrap().is_ascii());
        assert_eq!(factory.get_base(4, TYPE_INT).unwrap(), factory.find_by_name("int").unwrap().unwrap());
        assert_eq!(factory.get_base(8, TYPE_FLOAT).unwrap(), factory.find_by_name("double").unwrap().unwrap());
    }

    #[test]
    fn factory_concretize() {
        let factory = factory();
        let unknown = factory.get_base(1, TYPE_UNKNOWN).unwrap();
        let code = factory.get_type_code().unwrap();
        assert_eq!(code.get_metatype(), TYPE_CODE);
        assert_eq!(factory.concretize(code).unwrap(), unknown);
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        assert_eq!(factory.concretize(integer.clone()).unwrap(), integer);
    }

    #[test]
    fn factory_get_exact_piece_matrix() {
        let factory = factory();
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        let record = structure(&factory, "", 8, 4, vec![
            TypeField::new(0, 0, "a", integer.id()), TypeField::new(1, 4, "b", integer.id()),
        ]);
        assert_eq!(factory.get_exact_piece(record.clone(), 0, 8).unwrap(), Some(record.clone()));
        assert_eq!(factory.get_exact_piece(record.clone(), 4, 4).unwrap(), Some(integer));
        assert!(factory.get_exact_piece(record.clone(), 0, 2).unwrap().is_none());
        let partial = factory.get_exact_piece(record, 2, 4).unwrap().unwrap();
        assert_eq!(partial.get_metatype(), TYPE_PARTIALSTRUCT);
        assert_eq!(partial.get_size(), 4);
    }

    #[test]
    fn factory_partial_enum_is_recognised_as_enum() {
        let factory = factory();
        let enumeration = flags_enum(&factory);
        for (offset, size) in [(0, 1), (4, 4), (0, 4), (2, 1), (7, 1)] {
            let partial = factory.get_type_partial_enum(enumeration.clone(), offset, size).unwrap();
            assert!(partial.is_enum_type());
            assert_eq!(partial.get_metatype(), TYPE_UINT);
            assert_eq!(partial.get_sub_meta(), sub_metatype::SUB_UINT_PARTIALENUM);
            assert!(partial.has_stripped());
            assert_eq!(partial.get_size(), size);
        }
    }

    #[test]
    fn factory_get_exact_piece_enum_member_yields_partial_enum() {
        let factory = factory();
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        let enumeration = flags_enum(&factory);
        let record = structure(&factory, "", 16, 8, vec![
            TypeField::new(0, 0, "a", integer.id()), TypeField::new(1, 4, "b", integer.id()),
            TypeField::new(2, 8, "flags", enumeration.id()),
        ]);
        assert_eq!(factory.get_exact_piece(record.clone(), 8, 8).unwrap(), Some(enumeration));
        let low = factory.get_exact_piece(record.clone(), 8, 1).unwrap().unwrap();
        assert!(low.is_enum_type());
        assert_eq!((low.get_metatype(), low.get_size()), (TYPE_UINT, 1));
        let high = factory.get_exact_piece(record, 12, 4).unwrap().unwrap();
        assert!(high.is_enum_type());
        assert_eq!((high.get_metatype(), high.get_size()), (TYPE_UINT, 4));
        assert_eq!(high.get_partial_offset(), Some(4));
    }

    #[test]
    fn dependent_order_nested_struct() {
        let factory = factory();
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        let inner = structure(&factory, "inner", 8, 4, vec![
            TypeField::new(0, 0, "a", integer.id()), TypeField::new(1, 4, "b", integer.id()),
        ]);
        let outer = structure(&factory, "outer", 16, 4, vec![
            TypeField::new(0, 0, "in_", inner.id()), TypeField::new(1, 8, "c", integer.id()),
            TypeField::new(2, 12, "d", integer.id()),
        ]);
        let order = factory.dependent_order();
        let position = |root: &TypeRoot| order.iter().position(|entry| entry == root).unwrap();
        assert!(position(&integer) < position(&inner));
        assert!(position(&inner) < position(&outer));
        for root in factory.graph.roots() { assert!(order.contains(&root)); }
    }

    #[test]
    fn dependent_order_pointer_cycle() {
        let factory = factory();
        let a = factory.get_type_struct("cycA").unwrap();
        let b = factory.get_type_struct("cycB").unwrap();
        let pb = factory.get_type_pointer(8, b.clone(), 1).unwrap();
        let pa = factory.get_type_pointer(8, a.clone(), 1).unwrap();
        assert_eq!(factory.assign_raw_fields_struct(&a, vec![TypeField::new(0, -1, "next_b", pb.id())], vec![]).unwrap(), a);
        assert_eq!(factory.assign_raw_fields_struct(&b, vec![TypeField::new(0, -1, "next_a", pa.id())], vec![]).unwrap(), b);
        let order = factory.dependent_order();
        let mut seen = std::collections::HashSet::new();
        for root in &order { assert!(seen.insert(root.id()), "datatype appears twice in dependency order"); }
        for root in [&a, &b, &pa, &pb] { assert!(order.contains(root)); }
        for root in factory.graph.roots() { assert!(order.contains(&root)); }
    }

    #[test]
    fn factory_get_ptr_to_from_parent() {
        let factory = factory();
        let unknown = factory.get_base(1, TYPE_UNKNOWN).unwrap();
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        let float = factory.get_base(4, TYPE_FLOAT).unwrap();
        let record = structure(&factory, "", 16, 4, vec![
            TypeField::new(0, 0, "a", integer.id()), TypeField::new(1, 4, "b", float.id()),
            TypeField::new(2, 8, "c", integer.id()), TypeField::new(3, 12, "d", integer.id()),
        ]);
        assert_eq!(factory.get_ptr_to_from_parent(record.clone(), 8).unwrap(), integer);
        assert_eq!(factory.get_ptr_to_from_parent(record.clone(), 4).unwrap(), float);
        assert_eq!(factory.get_ptr_to_from_parent(record.clone(), 0).unwrap(), unknown);
        assert_eq!(factory.get_ptr_to_from_parent(record, 100).unwrap(), unknown);
    }

    #[test]
    fn factory_down_chain_matrix() {
        let factory = factory();
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        let record = structure(&factory, "", 8, 4, vec![
            TypeField::new(0, 0, "a", integer.id()), TypeField::new(1, 4, "b", integer.id()),
        ]);
        let pointer = factory.get_type_pointer(8, record, 1).unwrap();
        let (result, offset, parent, parent_offset) = factory.down_chain(&pointer, 4, false).unwrap();
        assert_eq!(result.unwrap().get_ptr_to(), Some(integer.clone()));
        assert_eq!((offset, parent_offset), (0, 4));
        assert_eq!(parent, Some(pointer));
        let array = factory.get_type_array(4, integer.clone()).unwrap();
        let pointer = factory.get_type_pointer(8, array, 1).unwrap();
        let (result, offset, _, _) = factory.down_chain(&pointer, 8, false).unwrap();
        assert_eq!(result.unwrap().get_ptr_to(), Some(integer));
        assert_eq!(offset, 0);
    }


    #[test]
    fn implicit_tag_typedef_preserves_identity_but_explicit_host_alias_does_not() {
        let factory = factory();
        let node = factory.get_type_struct("Node").unwrap();
        factory.set_fields_struct_raw(&node, vec![], vec![], 8, 8, 0).unwrap();
        assert_eq!(factory.get_typedef(&node, "Node", 0, 0).unwrap(), node);
        let alias = factory.get_typedef(&node, "Node", 0x1a2b, 0).unwrap();
        assert_ne!(alias.id(), node.id());
        assert_eq!(alias.get_id(), 0x1a2b);
        assert_eq!(alias.get_typedef(), Some(node));
    }

    #[test]
    fn sized_opaque_aggregate_completes_in_place_without_premature_layout() {
        let factory = factory();
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        let shell = factory.get_type_struct("Opaque").unwrap();
        let pointer = factory.get_type_pointer(8, shell.clone(), 1).unwrap();
        let alias = factory.get_typedef(&shell, "OpaqueAlias", 0, 0).unwrap();
        let array = factory.get_type_array(2, shell.clone()).unwrap();
        let parent = factory.get_type_struct("Parent").unwrap();
        factory.set_fields_struct_raw(
            &parent, vec![TypeField::new(0, 8, "value", shell.id())], vec![], 16, 8, 0,
        ).unwrap();
        let published = factory.set_fields_struct_raw(
            &shell, vec![], vec![], 8, 8, flags::type_incomplete,
        ).unwrap();
        assert_eq!(published, shell);
        assert_eq!((shell.get_size(), shell.get_alignment()), (8, 8));
        assert_eq!(alias.get_size(), 8);
        for root in [&shell, &array, &parent] {
            assert_eq!(factory.state(root).unwrap(), TypeState::Pending);
        }
        for root in [&shell, &alias, &array, &parent] {
            assert!(root.is_incomplete());
            assert!(!root.read().layout_ready(root.id()).unwrap());
            assert!(!root.read().derived_ready(root.id()).unwrap());
        }
        assert!(pointer.read().layout_ready(pointer.id()).unwrap());

        // Explicit incompleteness must not bypass field validation, and a
        // rejected replacement must retain the published provisional width.
        assert!(factory.set_fields_struct_raw(
            &shell, vec![TypeField::new(0, 8, "bad", integer.id())], vec![], 8, 8,
            flags::type_incomplete,
        ).is_err());
        // This body is valid alone, but would overrun the held parent's field.
        assert!(factory.set_fields_struct_raw(
            &shell, vec![TypeField::new(0, 0, "value", integer.id())], vec![], 16, 8, 0,
        ).is_err());
        assert_eq!(factory.state(&shell).unwrap(), TypeState::Pending);
        assert_eq!(shell.get_size(), 8);
        assert!(shell.is_incomplete());

        let completed = factory.set_fields_struct_raw(
            &shell, vec![TypeField::new(0, 0, "value", integer.id())], vec![], 8, 8, 0,
        ).unwrap();
        assert_eq!(completed, shell);
        assert_eq!(pointer.get_ptr_to(), Some(shell.clone()));
        assert_eq!(factory.get_type_array(2, shell.clone()).unwrap(), array);
        assert_eq!(array.get_size(), 16);
        assert_eq!(alias.get_typedef(), Some(shell.clone()));
        for root in [&shell, &alias, &array, &parent] {
            assert_eq!(factory.state(root).unwrap(), TypeState::Complete);
            assert!(!root.is_incomplete());
            assert!(root.read().layout_ready(root.id()).unwrap());
            assert!(root.read().derived_ready(root.id()).unwrap());
        }
        assert!(factory.set_fields_struct_raw(&shell, vec![], vec![], 8, 8, 0).is_err());
    }

    #[test]
    fn recursive_array_updates_layout_without_changing_identity() {
        let factory = TypeFactoryImpl::new();
        let node = factory.get_type_struct("N").unwrap();
        let array = factory.get_type_array(2, node.clone()).unwrap();
        let array_id = array.id();
        let next = factory.get_type_pointer(8, array.clone(), 1).unwrap();
        assert_eq!(next.get_size(), 8);
        assert_eq!(next.get_ptr_to(), Some(array.clone()));

        factory.begin(&node).unwrap();
        factory.set_fields_struct_raw(
            &node,
            vec![TypeField::new(0, 0, "next", next.id())],
            vec![],
            8,
            8,
            0,
        ).unwrap();

        assert_eq!((node.get_size(), node.get_alignment()), (8, 8));
        assert_eq!((array.get_size(), array.get_alignment()), (16, 8));
        assert_eq!(array.get_array_base(), Some(node.clone()));
        assert_eq!(factory.get_type_array(2, node).unwrap().id(), array_id);
    }

    #[test]
    fn failed_named_construction_is_hidden_and_retries_same_reservation() {
        let factory = TypeFactoryImpl::new();
        let original = factory.get_type_struct("S").unwrap();
        let reserved_id = original.id();
        factory.destroy_type(&original).unwrap();
        assert!(factory.find_by_name("S").unwrap().is_none());

        let retry = factory.get_type_struct("S").unwrap();
        assert_eq!(retry.id(), reserved_id);
        factory.begin(&retry).unwrap();
        let integer = factory.get_base(4, TYPE_INT).unwrap();
        let mut draft = Datatype::new_with_align(4, 4, TYPE_STRUCT);
        draft.name = "S".to_owned();
        draft.display_name = "S".to_owned();
        draft.id = retry.get_id();
        draft.kind = DatatypeKind::Struct {
            field: vec![TypeField::new(0, 0, "value", integer.id())],
            bitfield: vec![],
        };
        factory.complete(&retry, draft).unwrap();

        assert_eq!(factory.find_by_name("S").unwrap(), Some(retry));
        assert_eq!(original.get_size(), 4);
        assert_eq!(factory.state(&original).unwrap(), TypeState::Complete);
    }
}

