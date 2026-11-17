//! Fixed CP-P2 permutation. P3 archive0d803737, MIT OR Apache-2.0.
//! No claim follows from the parameter generator's nominal classicalM256 label.
#![allow(deprecated)]
use p3_air::{Air, AirBuilder, RowWindow, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Layers, Goldilocks as F};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use serde::Deserialize;
use std::sync::LazyLock;

pub const P: u64 = 0xffff_ffff_0000_0001;
pub const WIDTH: usize = 16;
pub const PERM_COLS: usize = 320;
pub type PermAir = Poseidon2Air<F, Layers, 16, 7, 1, 4, 24>;

#[derive(Deserialize)]
struct Constants {
    RF: usize,
    RP: usize,
    constants: Vec<u64>,
}
#[allow(non_snake_case)]
static WORDS: LazyLock<Vec<u64>> = LazyLock::new(|| {
    let c: Constants = serde_json::from_slice(include_bytes!("../data/round-constants.json"))
        .expect("pinned parameter JSON");
    assert_eq!((c.RF, c.RP, c.constants.len()), (8, 24, 152));
    assert!(c.constants.iter().all(|&v| v < P));
    c.constants
});

pub fn constants() -> RoundConstants<F, 16, 4, 24> {
    RoundConstants::new(
        core::array::from_fn(|r| core::array::from_fn(|j| F::from_u64(WORDS[r * 16 + j]))),
        core::array::from_fn(|r| F::from_u64(WORDS[64 + r])),
        core::array::from_fn(|r| core::array::from_fn(|j| F::from_u64(WORDS[88 + r * 16 + j]))),
    )
}
pub fn air() -> PermAir {
    Poseidon2Air::new(constants())
}

/// Native computation uses the pinned P3 linear layers; Python supplies an independent matrix reference.
pub fn permute(mut x: [F; 16]) -> [F; 16] {
    Layers::external_linear_layer(&mut x);
    for r in 0..4 {
        for j in 0..16 {
            x[j] = (x[j] + F::from_u64(WORDS[r * 16 + j])).exp_const_u64::<7>();
        }
        Layers::external_linear_layer(&mut x);
    }
    for r in 0..24 {
        x[0] = (x[0] + F::from_u64(WORDS[64 + r])).exp_const_u64::<7>();
        Layers::internal_linear_layer(&mut x);
    }
    for r in 0..4 {
        for j in 0..16 {
            x[j] = (x[j] + F::from_u64(WORDS[88 + r * 16 + j])).exp_const_u64::<7>();
        }
        Layers::external_linear_layer(&mut x);
    }
    x
}

/// Delegate the real source AIR unchanged to its exact320-column row prefix.
/// Based on P3 FilteredAirBuilder's forwarding pattern; this changes only the main window.
struct PrefixBuilder<'a, AB: AirBuilder> {
    inner: &'a mut AB,
    main: RowWindow<'a, AB::Var>,
}
impl<'a, AB: AirBuilder> AirBuilder for PrefixBuilder<'a, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type MainWindow = RowWindow<'a, AB::Var>;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        self.main
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x)
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}
pub fn eval_prefix<AB: AirBuilder<F = F>>(air: &PermAir, builder: &mut AB) {
    let window = builder.main();
    let main = RowWindow::from_two_rows(
        &window.current_slice()[..PERM_COLS],
        &window.next_slice()[..PERM_COLS],
    );
    air.eval(&mut PrefixBuilder {
        inner: builder,
        main,
    });
}
