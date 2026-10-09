use super::*;
use crate::context::{ArchContext as ContextArch, TypeOp};
use crate::dtype::Datatype;
use crate::funcdata::Funcdata;
use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::space::{addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace};
use kuna_num::opcodes::OpCode;
use kuna_sleigh::globalcontext::ContextInternal;
use kuna_sleigh::loadimage::LoadImage;
use kuna_sleigh::sleigh::Sleigh;
use std::rc::Rc;

    struct DummyImg;
    impl LoadImage for DummyImg {
        fn get_file_name(&self) -> &str {
            "dummy"
        }
        fn load_fill(&mut self, _ptr: &mut [u8], _addr: &Address) -> KunaResult<()> {
            Err(KunaError::data_unavail("dummy"))
        }
        fn get_arch_type(&self) -> Vec<u8> {
            Vec::new()
        }
        fn adjust_vma(&mut self, _adjust: i64) {}
    }

    pub(super) fn bare_arch() -> crate::architecture::Architecture {
        let arch = crate::architecture::Architecture::new(
            "t",
            Sleigh::new(Box::new(DummyImg), Box::new(ContextInternal::new())),
        );
        arch.types_impl().setup_sizes(Some(4), 8, 8);
        arch.types_impl().set_max_basetype_size(16);
        arch
    }

    pub(super) fn build_manager() -> AddrSpaceManager {
        let mut m = AddrSpaceManager::new();
        m.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        m.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
        m.insert_space(Rc::new(AddrSpace::new(
            spacetype::IPTR_PROCESSOR,
            "ram",
            false,
            8,
            1,
            2,
            addrspace_flags::hasphysical,
            1,
            1,
        )))
        .unwrap();
        m
    }

    pub(super) fn build_fd() -> Funcdata {
        let manage = build_manager();
        let glb = Rc::new(ContextArch::new(manage));
        let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
        let addr = Address::new(ram, 0x1000);
        Funcdata::new("func", "func", glb, addr, 0x1000_0000, 0x40).unwrap()
    }

    pub(super) fn ram(fd: &Funcdata) -> Rc<AddrSpace> {
        Rc::clone(fd.get_arch().manage().get_space_by_name("ram").unwrap())
    }

    pub(super) fn mk_op(fd: &mut Funcdata, inputs: int4, off: u64, opc: OpCode) -> OpId {
        let r = ram(fd);
        let op = fd.new_op(inputs, Address::new(r, off));
        fd.obank_mut().change_opcode(op, TypeOp::new(opc, 0, format!("{opc:?}")));
        op
    }

    pub(super) fn named_call_input(
        fd: &mut Funcdata, name: &str, ty: Rc<Datatype>,
    ) -> crate::context::VarnodeId {
        let slot = fd.get_func_proto().num_params();
        let addr = Address::new(ram(fd), 0x800 + slot as u64 * 0x20);
        fd.get_func_proto_mut().set_param(slot, name, &crate::fspec::ParameterPieces {
            addr: addr.clone(), type_: Some(ty.clone()),
            flags: crate::fspec::parameter_pieces_flags::TYPELOCK
                | crate::fspec::parameter_pieces_flags::NAMELOCK,
        });
        fd.link_proto_params();
        let vn = fd.new_varnode(ty.get_size(), &addr, Some(ty));
        let vn = fd.set_input_varnode(vn).unwrap();
        fd.vbank_mut().get_mut(vn).unwrap().set_explicit();
        let high = fd.vbank().get(vn).unwrap().get_high().unwrap();
        fd.high_bank_mut().get_mut(high).unwrap().set_kuna_name(name);
        vn
    }

    pub(super) fn name_call_local(fd: &mut Funcdata, vn: crate::context::VarnodeId, name: &str) {
        fd.vbank_mut().get_mut(vn).unwrap().set_explicit();
        let high = fd.vbank().get(vn).unwrap().get_high().unwrap();
        fd.high_bank_mut().get_mut(high).unwrap().set_kuna_name(name);
    }

    pub(super) fn execution_printer(arch: &crate::architecture::Architecture, rust: bool) -> PrintC {
        let lang = if rust { crate::kuna_lang::OutLang::Rust } else { crate::kuna_lang::OutLang::C };
        let mut print = PrintC::new();
        print.set_name(lang.print_name());
        print.rt_ctx = RealTypeCtx::from_arch(arch, lang);
        print.set_output_stream();
        print
    }

pub(super) fn assert_c_source(source: &str, label: &str) {
    let dir = std::env::temp_dir()
        .join(format!("kuna-emitted-c-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    kuna_harness::c_behavior::assert_c_behavior(&dir.join("consumer.c"), "", source, "");
    std::fs::remove_dir_all(dir).unwrap();
}

pub(super) fn assert_rust_source(source: &str, label: &str) {
    use std::process::Command;
    let dir = std::env::temp_dir()
        .join(format!("kuna-emitted-rust-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("consumer.rs");
    std::fs::write(&input, source).unwrap();
    for optimization in ["0", "2"] {
        let executable = dir.join(format!("consumer-{optimization}"));
        let built = Command::new("rustc")
            .args(["--edition=2021", "-A", "warnings", "-C"])
            .arg(format!("opt-level={optimization}"))
            .arg(&input).arg("-o").arg(&executable).output()
            .expect("required Rust compiler");
        assert!(built.status.success(), "{label}/Rust/O{optimization}:\n{}\n{source}",
            String::from_utf8_lossy(&built.stderr));
        let ran = Command::new(&executable).output().expect("execute emitted Rust");
        assert!(ran.status.success(), "{label}/Rust/O{optimization}:\n{}\n{source}",
            String::from_utf8_lossy(&ran.stderr));
    }
    std::fs::remove_dir_all(dir).unwrap();
}
