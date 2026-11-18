// Added under cfg(test) only. Decode the published runtime's outer envelope,
// then dispatch its unchanged pallet call in the upstream TestExternalities.
use crate::{mock::*, Call, LeafBlocks, PoolValue, UsedNullifiers, POOL_STEP};
use codec::{Compact, Decode};
use frame_support::assert_ok;
use qnero_circuit::HeaderInputs;
use qnero_note_core::Digest;
use sp_core::H256;
use sp_runtime::{traits::{Dispatchable, ValidateUnsigned}, transaction_validity::TransactionSource};
use std::{env, fs, path::Path};

#[test]
fn funded_public_wallet_dispatch() {
    let root = env::var("QNERO_PUBLIC").expect("public input directory");
    let read = |name: &str| fs::read(Path::new(&root).join(name)).expect("public artifact");
    let inner: [u8; 32] = read("funding-inner.bin").try_into().unwrap();
    let funded: [u8; 32] = read("funding-commitment.bin").try_into().unwrap();
    let bytes = read("payment.scale");
    let mut c = &bytes[..];
    assert_eq!(Compact::<u32>::decode(&mut c).unwrap().0 as usize, c.len());
    assert_eq!(&c[..2], &[4, 24]); // canonical bare preamble and runtime pallet index
    c = &c[2..];
    let call = Call::<Test>::decode(&mut c).expect("wallet call SCALE-decodes");
    assert!(c.is_empty());
    assert!(matches!(&call, Call::submit_private_batch {..}));
    let header = read("anchor-fields.bin");
    assert_eq!(header.len(), 242);
    let word = |start: usize| -> [u8; 32] { header[start..start + 32].try_into().unwrap() };
    let height = u32::from_le_bytes(header[32..36].try_into().unwrap());
    let parsed = HeaderInputs::new(Digest::from_bytes(&word(0)).unwrap(), height,
        word(36), word(68), Digest::from_bytes(&word(100)).unwrap(), &header[132..]).unwrap();
    assert_eq!(height, 2);
    assert_eq!(parsed.block_hash().to_bytes().as_slice(), read("anchor.bin"));
    let expected = read("commitments.bin");
    let nfs = read("real-slot-nullifiers.bin");
    assert_eq!(nfs.len(), 64);
    new_test_ext().execute_with(|| {
        // Mint the funded leaf through the reward sink. The mint amount and
        // anchor are explicit laboratory starting state, not PoW/emission.
        System::set_block_number(1);
        set_author_preimage([3; 32]);
        assert_ok!(Shielded::coinbase(RuntimeOrigin::none(), inner, Vec::new()));
        assert_ok!(<Shielded as qp_coinbase::CoinbaseSink<u128>>::deposit_coinbase(1000 * POOL_STEP));
        ZkTree::process_pending_leaves();
        assert_eq!(ZkTree::leaf_count(), 1);
        assert_eq!(ZkTree::leaf(0).unwrap(), funded);
        assert_eq!(ZkTree::root(), parsed.zk_tree_root.to_bytes());
        assert_eq!(Shielded::coinbase_value(0), Some(1000));
        assert_eq!(PoolValue::<Test>::get(), 1000 * POOL_STEP);
        frame_system::BlockHash::<Test>::insert(u64::from(height), H256::from(parsed.block_hash().to_bytes()));
        System::set_block_number(u64::from(height + 1));
        assert_ok!(<Shielded as ValidateUnsigned>::validate_unsigned(TransactionSource::External, &call));
        assert_ok!(<Shielded as ValidateUnsigned>::pre_dispatch(&call));
        let transaction = RuntimeCall::Shielded(call.clone());
        assert_ok!(transaction.clone().dispatch(RuntimeOrigin::none()));
        assert_eq!(PoolValue::<Test>::get(), 992 * POOL_STEP);
        assert_eq!(Shielded::pending_coinbase_fee(), 4 * POOL_STEP);
        assert_eq!(UsedNullifiers::<Test>::iter().count(), 2);
        for nf in nfs.chunks_exact(32) {
            let word: [u8; 32] = nf.try_into().unwrap();
            assert!(UsedNullifiers::<Test>::contains_key(word));
        }
        assert_eq!(ZkTree::leaf_count(), 3);
        assert_eq!(ZkTree::leaf(1).unwrap().as_slice(), &expected[..32]);
        assert_eq!(ZkTree::leaf(2).unwrap().as_slice(), &expected[32..]);
        assert_eq!(LeafBlocks::<Test>::get(1), Some(3));
        assert_eq!(LeafBlocks::<Test>::get(2), Some(3));
        ZkTree::process_pending_leaves();
        let final_root = ZkTree::root();
        for i in [1, 2] {
            assert!(ZkTree::verify_proof(ZkTree::leaf(i).unwrap(), &ZkTree::get_merkle_proof(i).unwrap()));
        }
        assert!(<Shielded as ValidateUnsigned>::validate_unsigned(TransactionSource::External, &call).is_err());
        assert!(<Shielded as ValidateUnsigned>::pre_dispatch(&call).is_err());
        assert!(transaction.dispatch(RuntimeOrigin::none()).is_err());
        assert_eq!(UsedNullifiers::<Test>::iter().count(), 2);
        assert_eq!(ZkTree::leaf_count(), 3);
        assert_eq!(ZkTree::root(), final_root);
        assert_eq!(PoolValue::<Test>::get(), 992 * POOL_STEP);
        assert_eq!(Shielded::pending_coinbase_fee(), 4 * POOL_STEP);
        println!("{{\"minted_steps\":1000,\"remaining_pool_steps\":992,\"fee_steps\":8,\"burned_steps\":4,\"pending_author_steps\":4,\"leaves_after\":3,\"settled_nullifiers\":2,\"output_membership_checked\":true,\"pool_and_pre_dispatch_passed\":true,\"replay_refused_by_all_three_paths\":true,\"final_tree_root\":\"{}\"}}", hex::encode(final_root));
    });
}
