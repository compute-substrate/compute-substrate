use anyhow::Result;
use tempfile::TempDir;

use csd::chain::reorg::maybe_reorg_to;
use csd::state::db::get_tip;
use csd::types::Hash32;

mod testutil_chain;
use testutil_chain::*;

#[test]
fn reorg_restores_transactions_from_old_branch_to_mempool() -> Result<()> {

    let tmp = TempDir::new()?;
    let (db, mp) = setup_chain(tmp.path())?;

    /*
        Build chain:

        genesis
          |
          A1
          |
          A2  (contains tx)
    */

    let a1 = mine_block(&db, &mp)?;
    let tx = create_test_tx(&db)?;
    mp.insert(tx.clone())?;

    let a2 = mine_block(&db, &mp)?;
    assert_eq!(mp.len(), 0, "tx should be mined and removed from mempool");

    /*
        Build competing chain

        genesis
          |
          B1 -> B2 -> B3
    */

    let b1 = mine_block_on_parent(&db, &mp, genesis_hash())?;
    let b2 = mine_block_on_parent(&db, &mp, b1)?;
    let b3 = mine_block_on_parent(&db, &mp, b2)?;

    /*
        Reorg to longer chain
    */

    maybe_reorg_to(&db, &b3, Some(&mp))?;

    let tip = get_tip(&db)?;
    assert_eq!(tip, b3);

    /*
        TX from old chain must reappear in mempool
    */

    assert_eq!(
        mp.len(),
        1,
        "tx from orphaned block must return to mempool"
    );

    Ok(())
}
