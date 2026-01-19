use anyhow::{Result, bail};
use crate::types::{Hash32, Block};
use crate::state::db::{Stores, get_tip, set_tip, k_block};
use crate::chain::index::{get_hidx, HeaderIndex};
use crate::state::utxo::{validate_and_apply_block, undo_block};
use crate::state::app::current_epoch;

fn load_block(db: &Stores, hash: &Hash32) -> Result<Block> {
    let Some(v) = db.blocks.get(k_block(hash))? else { bail!("missing block"); };
    Ok(bincode::deserialize(&v)?)
}

fn find_ancestor(db: &Stores, mut a: HeaderIndex, mut b: HeaderIndex) -> Result<HeaderIndex> {
    while a.height > b.height {
        a = get_hidx(db, &a.parent)?.ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    }
    while b.height > a.height {
        b = get_hidx(db, &b.parent)?.ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    }
    while a.hash != b.hash {
        a = get_hidx(db, &a.parent)?.ok_or_else(|| anyhow::anyhow!("missing parent"))?;
        b = get_hidx(db, &b.parent)?.ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    }
    Ok(a)
}

pub fn maybe_reorg_to(db: &Stores, new_tip: &Hash32) -> Result<()> {
    let cur_tip = match get_tip(db)? {
        Some(t) => t,
        None => {
            set_tip(db, new_tip)?;
            return Ok(());
        }
    };

    if cur_tip == *new_tip { return Ok(()); }

    let cur_hi = get_hidx(db, &cur_tip)?.ok_or_else(|| anyhow::anyhow!("missing cur tip idx"))?;
    let new_hi = get_hidx(db, new_tip)?.ok_or_else(|| anyhow::anyhow!("missing new tip idx"))?;

    // Only reorg if strictly higher chainwork
    if new_hi.chainwork <= cur_hi.chainwork { return Ok(()); }

    let anc = find_ancestor(db, cur_hi.clone(), new_hi.clone())?;

    // 1) collect blocks to undo: cur_tip -> anc (exclusive)
    let mut undo_hashes: Vec<Hash32> = vec![];
    let mut h = cur_hi;
    while h.hash != anc.hash {
        undo_hashes.push(h.hash);
        h = get_hidx(db, &h.parent)?.ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    }

    // 2) collect blocks to apply: anc -> new_tip (exclusive), in forward order
    let mut apply_hashes: Vec<Hash32> = vec![];
    let mut h2 = new_hi;
    while h2.hash != anc.hash {
        apply_hashes.push(h2.hash);
        h2 = get_hidx(db, &h2.parent)?.ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    }
    apply_hashes.reverse();

    // Undo
    for bh in undo_hashes {
        undo_block(db, &bh)?;
    }

    // Apply
    for bh in apply_hashes {
        let blk = load_block(db, &bh)?;
        let epoch = current_epoch(get_hidx(db, &bh)?.unwrap().height);
        validate_and_apply_block(db, &blk, epoch)?;
    }

    set_tip(db, new_tip)?;
    Ok(())
}
