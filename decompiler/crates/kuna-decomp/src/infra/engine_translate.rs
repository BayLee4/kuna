//! The `Architecture`↔translator seam: the [`EngineTranslate`] trait.
//!
//! [`Architecture`](crate::architecture::Architecture) owns its disassembly
//! engine behind a `Box<dyn EngineTranslate>` trait object rather than a
//! concrete [`Sleigh`], so the ghidra-mode translator (p-code fetched
//! from the Java host per instruction, no local `.sla`) is installed in
//! its place without `kuna-decomp` naming any ghidra-specific type — the
//! ghidra translator lives in the downstream `kuna-ghidra` crate, so an enum
//! variant would be a dependency cycle, but a trait object owned here is not.
//! See `docs/rust-port/ghidra-phase2-plan.md` §2.2.
//!
//! The trait extends [`Translate`] (already `: RegisterLookup`), adding only
//! the handful of engine-owned surfaces `Architecture` and its external
//! callers reach beyond the abstract `Translate` API: the address-space
//! manager handles, the load image, the context database, and the
//! register-storage lookup.  Everything the callers reach through
//! `Translate`/`RegisterLookup` (endianness, float formats, `oneInstruction`,
//! register *names*, …) needs no new method here.
//!
//! [`Sleigh`] forwards to its engine methods; the Ghidra implementation uses
//! host callbacks through the same fallible boundary.

use std::cell::RefCell;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::space::AddrSpaceManager;
use kuna_base::types::int4;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::globalcontext::ContextDatabase;
use kuna_sleigh::loadimage::LoadImage;
use kuna_sleigh::sleigh::Sleigh;
use kuna_sleigh::translate::{PcodeEmit, Translate};

use crate::pcodeinject::{
    InjectContext, CALLFIXUP_TYPE, CALLMECHANISM_TYPE, CALLOTHERFIXUP_TYPE,
};

/// The seam between [`Architecture`](crate::architecture::Architecture) and
/// its disassembly engine (see the module docs).
pub trait EngineTranslate: Translate {
    /// Borrow the engine's address-space manager (C++ the `Architecture`
    /// IS-A `AddrSpaceManager`; in the Rust port it lives inside the engine
    /// and `Architecture::manage()` forwards here).
    fn manager(&self) -> &AddrSpaceManager;

    /// Share the engine's single address-space manager (LOSS-132): the `Rc`
    /// the lift populated, handed to `glb` so every subsystem keys state by
    /// the same space identities/indices.
    fn manager_rc(&self) -> Rc<AddrSpaceManager>;

    /// Mutably borrow the engine's address-space manager — used during init
    /// to insert the analysis-only fspec/iop/join spaces (C++
    /// `Architecture::restoreFromSpec`).
    fn manager_mut(&mut self) -> &mut AddrSpaceManager;

    /// Share the program load image (C++ `Architecture::loader`); the `Rc`
    /// aliases the engine's loader, so a shared handle stays current across
    /// `set_loader`.
    fn loader_rc(&self) -> Rc<RefCell<Box<dyn LoadImage>>>;

    /// Replace the load image (C++ `restoreFromSpec` hands the loader to the
    /// translator once the `.sla` is decoded).
    fn set_loader(&mut self, loader: Box<dyn LoadImage>);

    /// Share the callback capability for build-once executable injections.
    /// The architecture retains it; the library keeps only a Weak backedge.
    fn injection_resolver(&self) -> Option<Rc<dyn crate::pcodeinject::InjectPcodeResolver>> {
        None
    }

    /// Read a Varnode's-worth of bytes from the load image at `addr`, masked
    /// to `sz` (C++ `Emulate*::getLoadImageValue`); drives jump-table LOAD
    /// emulation.
    fn read_loadimage_value(&self, addr: &Address, sz: i32) -> KunaResult<u64>;

    /// Resolve a register by name to its [`VarnodeData`] storage (C++
    /// `Translate::getRegister(name)`).
    fn get_register_varnode(&self, nm: &[u8]) -> KunaResult<VarnodeData>;

    /// Speculative form of [`EngineTranslate::get_register_varnode`]: ask
    /// whether `nm` resolves *here*, cheaply and without side effects.
    ///
    /// `None` means "not resolvable on this translator", never "this language
    /// has no such register".  In ghidra mode the exact lookup is a
    /// `getRegister` query and the host answers an undefined name by throwing,
    /// so a pass merely testing "does this language happen to have X?" must
    /// use this instead — the ghidra translator answers it from its cache and
    /// issues no query.
    fn probe_register_varnode(&self, nm: &[u8]) -> Option<VarnodeData> {
        self.get_register_varnode(nm).ok()
    }

    /// Run a closure with mutable access to the engine's [`ContextDatabase`]
    /// (C++ `glb->context`).  The object-safe form of
    /// [`Sleigh::with_context_db_mut`]: it takes `&mut dyn FnMut` (rather than
    /// a generic closure) so the method stays callable on a trait object;
    /// [`Architecture::with_context_db_mut`](crate::architecture::Architecture::with_context_db_mut)
    /// keeps the generic, value-returning wrapper over it.
    fn with_context_db_dyn(&self, f: &mut dyn FnMut(&mut dyn ContextDatabase));

    /// Emit the p-code of a named injection payload fetched from the engine's
    /// back end (C++ `InjectPayloadGhidra::inject` ->
    /// `ArchitectureGhidra::getPcodeInject`).
    ///
    /// Reached only when the injection library holds no locally compiled
    /// template for the payload, which on a translator with no local `.sla`
    /// is always.  What comes back is p-code already lifted against
    /// `context` and bound to that one call site — never a reusable template,
    /// so it must be emitted straight through and not cached.
    ///
    /// The default errs: the standalone `Sleigh` compiles every registered
    /// payload at bootstrap, so a missing template there is a real failure.
    fn fetch_inject_pcode(
        &self,
        name: &[u8],
        ptype: int4,
        _context: &InjectContext,
        _emit: &mut dyn PcodeEmit,
    ) -> KunaResult<()> {
        let kind = match ptype {
            CALLFIXUP_TYPE => "call-fixup",
            CALLOTHERFIXUP_TYPE => "callother-fixup",
            CALLMECHANISM_TYPE => "call-mechanism",
            _ => "executable-pcode",
        };
        Err(KunaError::lowlevel(format!(
            "{kind} template not compiled and no back-end fetch: {}",
            String::from_utf8_lossy(name)
        )))
    }

    /// Downcast to the concrete standalone [`Sleigh`] engine when this
    /// translator is one (default `None`; the `Sleigh` impl returns `Some`).
    /// The standalone-only analysis / FID / console paths — which never run
    /// on a non-Sleigh engine — use this escape hatch to reach the
    /// Sleigh-specific surface (`SleighBase`, `instruction_mask`,
    /// `install_register_lookup`, …).
    fn as_sleigh(&self) -> Option<&Sleigh> {
        None
    }

    /// Mutable [`EngineTranslate::as_sleigh`].
    fn as_sleigh_mut(&mut self) -> Option<&mut Sleigh> {
        None
    }
}

impl EngineTranslate for Sleigh {
    fn manager(&self) -> &AddrSpaceManager {
        self.base().manager()
    }
    fn manager_rc(&self) -> Rc<AddrSpaceManager> {
        Sleigh::manager_rc(self)
    }
    fn manager_mut(&mut self) -> &mut AddrSpaceManager {
        self.base_mut().manager_mut()
    }
    fn loader_rc(&self) -> Rc<RefCell<Box<dyn LoadImage>>> {
        Sleigh::loader_rc(self)
    }
    fn set_loader(&mut self, loader: Box<dyn LoadImage>) {
        Sleigh::set_loader(self, loader)
    }
    fn read_loadimage_value(&self, addr: &Address, sz: i32) -> KunaResult<u64> {
        Sleigh::read_loadimage_value(self, addr, sz)
    }
    fn get_register_varnode(&self, nm: &[u8]) -> KunaResult<VarnodeData> {
        Sleigh::get_register_varnode(self, nm)
    }
    fn with_context_db_dyn(&self, f: &mut dyn FnMut(&mut dyn ContextDatabase)) {
        self.with_context_db_mut(|db| f(db));
    }
    fn as_sleigh(&self) -> Option<&Sleigh> {
        Some(self)
    }
    fn as_sleigh_mut(&mut self) -> Option<&mut Sleigh> {
        Some(self)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use kuna_base::space::{
        addrspace_flags, spacetype, AddrSpace, ConstantSpace, RegisterLookup,
        UniqueSpace, VarnodeStorage,
    };
    use kuna_sleigh::globalcontext::ContextInternal;
    use kuna_sleigh::translate::{AssemblyEmit, TranslateBase};

    struct EmptyImage;

    impl LoadImage for EmptyImage {
        fn get_file_name(&self) -> &str { "query-failure-test" }
        fn load_fill(&mut self, _bytes: &mut [u8], _at: &Address) -> KunaResult<()> {
            Err(KunaError::data_unavail("no local image"))
        }
        fn get_arch_type(&self) -> Vec<u8> { Vec::new() }
        fn adjust_vma(&mut self, _adjust: i64) {}
    }

    struct FailingTranslate {
        inner: Sleigh,
        terminal: bool,
        register_error: Option<KunaError>,
        queries: Rc<Cell<usize>>,
    }

    impl RegisterLookup for FailingTranslate {
        fn get_register(&self, name: &str) -> KunaResult<VarnodeStorage> {
            RegisterLookup::get_register(&self.inner, name)
        }
        fn get_register_name(&self, space: &Rc<AddrSpace>, offset: u64, size: i32) -> KunaResult<String> {
            RegisterLookup::get_register_name(&self.inner, space, offset, size)
        }
        fn get_exact_register_name(&self, space: &Rc<AddrSpace>, offset: u64, size: i32) -> KunaResult<String> {
            RegisterLookup::get_exact_register_name(&self.inner, space, offset, size)
        }
    }

    impl Translate for FailingTranslate {
        fn translate_base(&self) -> &TranslateBase { self.inner.translate_base() }
        fn translate_base_mut(&mut self) -> &mut TranslateBase { self.inner.translate_base_mut() }
        fn initialize(&mut self, store: &mut kuna_base::xml::DocumentStorage) -> KunaResult<()> {
            Translate::initialize(&mut self.inner, store)
        }
        #[allow(clippy::mutable_key_type)]
        fn get_all_registers(&self, registers: &mut BTreeMap<VarnodeData, String>) {
            self.inner.get_all_registers(registers);
        }
        fn get_user_op_names(&self, names: &mut Vec<String>) -> KunaResult<()> {
            self.inner.get_user_op_names(names)
        }
        fn instruction_length(&self, at: &Address) -> KunaResult<i32> {
            self.inner.instruction_length(at)
        }
        fn one_instruction(&self, _emit: &mut dyn PcodeEmit, _at: &Address) -> KunaResult<i32> {
            self.queries.set(self.queries.get() + 1);
            Err(if self.terminal {
                KunaError::transport("callback query failed")
            } else {
                KunaError::data_unavail("instruction unavailable")
            })
        }
        fn print_assembly(&self, emit: &mut dyn AssemblyEmit, at: &Address) -> KunaResult<i32> {
            self.inner.print_assembly(emit, at)
        }
    }

    impl EngineTranslate for FailingTranslate {
        fn manager(&self) -> &AddrSpaceManager { self.inner.base().manager() }
        fn manager_rc(&self) -> Rc<AddrSpaceManager> { self.inner.manager_rc() }
        fn manager_mut(&mut self) -> &mut AddrSpaceManager { self.inner.base_mut().manager_mut() }
        fn loader_rc(&self) -> Rc<RefCell<Box<dyn LoadImage>>> { self.inner.loader_rc() }
        fn set_loader(&mut self, loader: Box<dyn LoadImage>) { self.inner.set_loader(loader); }
        fn read_loadimage_value(&self, at: &Address, size: i32) -> KunaResult<u64> {
            self.inner.read_loadimage_value(at, size)
        }
        fn get_register_varnode(&self, name: &[u8]) -> KunaResult<VarnodeData> {
            if let Some(error) = &self.register_error {
                self.queries.set(self.queries.get() + 1);
                return Err(error.clone());
            }
            self.inner.get_register_varnode(name)
        }
        fn with_context_db_dyn(&self, f: &mut dyn FnMut(&mut dyn ContextDatabase)) {
            self.inner.with_context_db_mut(|db| f(db));
        }
    }

    /// A real Architecture boundary whose instruction acquisition fails once
    /// per query, without depending on a compiled language specification.
    pub(crate) fn failure_arch(
        terminal: bool,
    ) -> (crate::architecture::Architecture, Address, Rc<Cell<usize>>) {
        failure_arch_with_register_error(terminal, None, false)
    }

    fn failure_arch_with_register_error(
        terminal: bool,
        register_error: Option<KunaError>,
        has_ffree: bool,
    ) -> (crate::architecture::Architecture, Address, Rc<Cell<usize>>) {
        let mut inner = Sleigh::new(Box::new(EmptyImage), Box::new(ContextInternal::new()));
        let manager = inner.base_mut().manager_mut();
        manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        for (index, name) in [(1, "ram"), (2, "register")] {
            manager.insert_space(Rc::new(AddrSpace::new(
                spacetype::IPTR_PROCESSOR, name, false, 8, 1, index,
                addrspace_flags::hasphysical, 1, 1,
            ))).unwrap();
        }
        manager.insert_space(Rc::new(UniqueSpace::new(3, 0, false))).unwrap();
        manager.set_default_code_space(1).unwrap();
        let entry = Address::new(Rc::clone(manager.get_space_by_name("ram").unwrap()), 0x1000);
        let queries = Rc::new(Cell::new(0));
        let translate = FailingTranslate {
            inner, terminal, register_error, queries: Rc::clone(&queries),
        };
        let mut arch = crate::architecture::Architecture::from_engine_translate("test:LE:64", Box::new(translate));
        if has_ffree {
            Rc::get_mut(&mut arch.userops).expect("fresh architecture owns its userops")
                .register_op(crate::userop::UserPcodeOp::new_unspecialized(b"ffree", 0))
                .unwrap();
        }
        (arch, entry, queries)
    }

    #[test]
    fn x87_register_discovery_preserves_terminal_transport() {
        let (arch, entry, queries) = failure_arch_with_register_error(
            false, Some(KunaError::transport("x87 register query disconnected")), true,
        );
        let result = arch.new_funcdata("entry", entry, 0);
        assert_eq!(queries.get(), 1, "stop at the first failed register query");
        assert!(
            matches!(result, Err(KunaError::Transport { .. })),
            "terminal host failure must not become unavailable x87 capability",
        );
    }

    #[test]
    fn x87_register_discovery_preserves_decoder_failure() {
        let error = KunaError::Decoder { explain: "malformed x87 register storage".into() };
        let (arch, entry, queries) = failure_arch_with_register_error(
            false, Some(error.clone()), true,
        );
        assert_eq!(arch.new_funcdata("entry", entry, 0).err(), Some(error));
        assert_eq!(queries.get(), 1, "stop at the first malformed register reply");
    }

    #[test]
    fn x87_register_discovery_declines_ordinary_missing_register() {
        let (arch, entry, queries) = failure_arch_with_register_error(
            false, Some(KunaError::lowlevel("No register named ST0")), true,
        );
        let function = arch.new_funcdata("entry", entry, 0).unwrap();
        assert!(function.get_arch().x87_empty_storage.is_none());
        assert_eq!(queries.get(), 1);
    }

    #[test]
    fn x87_register_discovery_skips_languages_without_ffree() {
        let (arch, entry, queries) = failure_arch_with_register_error(
            false, Some(KunaError::transport("must not query this language")), false,
        );
        let function = arch.new_funcdata("entry", entry, 0).unwrap();
        assert!(function.get_arch().x87_empty_storage.is_none());
        assert_eq!(queries.get(), 0);
    }
}
