//! The no-return contract shared by flow construction and callee write probes.

use crate::architecture::Architecture;
use kuna_base::address::Address;

pub(crate) fn is_no_return(arch: &Architecture, entry: &Address) -> kuna_base::error::KunaResult<bool> {
    let remote = match arch.remote_scope.as_ref() {
        Some(remote) => remote.function_at(entry)?,
        None => None,
    };
    if remote.as_ref().is_some_and(|facts| facts.no_return)
        || arch.symboltab.function_is_no_return_across_scopes(entry)
    {
        return Ok(true);
    }
    let name = arch.symboltab.function_display_name_across_scopes(entry);
    if let Some(name) = name.as_deref() {
        if arch.noreturn_extern_match
            && crate::kuna_noreturn_externmatch::is_known_noreturn_name(name)
        {
            return Ok(true);
        }
        if arch.strip_security_check && crate::kuna_securitycheck::is_security_check_name(name) {
            return Ok(true);
        }
    }
    if arch.noreturn_extern_calls {
        let name = remote.map(|facts| facts.display_name).or(name);
        return Ok(name
            .as_deref()
            .is_some_and(crate::kuna_noreturnextern::matches_noreturn_extern_name));
    }
    Ok(false)
}
