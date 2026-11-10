//! Run `cargo run --example ue -- --list` to list resolvers.
//! Run `cargo run --example ue -- <binary> [resolver names...]` to resolve them.
//! Upstream resolvers: <https://github.com/Jacoby6000/patternsleuth/tree/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal>
use anyhow::{Context, Result, bail};
use patternsleuth::resolvers::DynResolverFactory;

use patternsleuth::image::Image;

#[path = "mod.rs"]
pub mod ue;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .context("usage: ue <binary|--list> [resolver names...]")?;
    let factories = ue::factories();
    if path == "--list" {
        for factory in factories {
            println!("{}", factory().name);
        }
        return Ok(());
    }
    let names: Vec<_> = args.collect();
    for name in &names {
        if !factories.iter().any(|factory| factory().name == name) {
            bail!("unknown resolver: {name}");
        }
    }
    let factories: Vec<fn() -> &'static DynResolverFactory> = factories
        .into_iter()
        .filter(|factory| names.is_empty() || names.iter().any(|name| name == factory().name))
        .collect();
    let bytes = std::fs::read(&path).with_context(|| format!("read {path}"))?;
    let image = Image::builder().functions(true).build(&bytes)?;
    let results = image.resolve_many(&factories);
    let mut failed = false;
    for (factory, result) in factories.iter().zip(results) {
        match result {
            Ok(value) => println!("{}: {value:?}", factory().name),
            Err(error) => {
                failed = true;
                eprintln!("{}: {error}", factory().name);
            }
        }
    }
    if failed {
        bail!("one or more resolvers failed");
    }
    Ok(())
}
