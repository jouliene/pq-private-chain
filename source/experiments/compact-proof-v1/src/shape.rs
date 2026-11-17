//! Trusted binary-FRI, cap-height-zero, EF5, salt8, all-PoW-zero grammar.
use crate::codec::Error;

#[derive(Clone, Debug)]
pub struct TrustedShape {
    pub(crate) main_width: usize,
    pub(crate) fixed_width: usize,
    pub(crate) chunks: usize,
    pub(crate) original_log_rows: usize,
    pub(crate) log_blowup: usize,
    pub(crate) queries: usize,
    pub(crate) max_wire_bytes: usize,
}

impl TrustedShape {
    /// The caller must derive these values from the approved AIR/configuration.
    /// Main and fixed next-row openings are mandatory in this specific grammar.
    pub fn new(
        main_width: usize,
        fixed_width: usize,
        chunks: usize,
        original_log_rows: usize,
        log_blowup: usize,
        queries: usize,
        max_wire_bytes: usize,
    ) -> Result<Self, Error> {
        if main_width == 0
            || fixed_width == 0
            || chunks < 2
            || !chunks.is_power_of_two()
            || queries == 0
            || original_log_rows == 0
            || original_log_rows > 30
            || log_blowup == 0
            || log_blowup > 31
            || original_log_rows
                .checked_add(1)
                .and_then(|x| x.checked_add(log_blowup))
                .is_none_or(|x| x > 32)
            || max_wire_bytes == 0
            || max_wire_bytes > 8 * 1024 * 1024
        {
            return Err(Error::Shape);
        }
        let n = 1usize
            .checked_shl(original_log_rows as u32)
            .ok_or(Error::Overflow)?;
        let budget = queries
            .checked_add(10)
            .and_then(|x| x.checked_mul(2))
            .ok_or(Error::Overflow)?;
        if budget > n {
            return Err(Error::Shape);
        }
        let shape = Self {
            main_width,
            fixed_width,
            chunks,
            original_log_rows,
            log_blowup,
            queries,
            max_wire_bytes,
        };
        // Bound every fixed dimension by the caller's byte cap, including tiny
        // truncated inputs. No proof bytes can select any of these dimensions.
        if shape.minimum_bytes()? > max_wire_bytes {
            return Err(Error::Limit);
        }
        Ok(shape)
    }

    pub fn degree_bits(&self) -> usize {
        self.original_log_rows + 1
    }
    pub fn folds(&self) -> usize {
        self.degree_bits()
    }
    pub fn lde_log(&self) -> usize {
        self.degree_bits() + self.log_blowup
    }
    pub fn input_widths(&self, batch: usize) -> Vec<usize> {
        match batch {
            0 => vec![10],
            1 => vec![self.main_width + 5],
            2 => vec![10; self.chunks],
            3 => vec![self.fixed_width],
            _ => unreachable!("trusted four-batch layout"),
        }
    }
    pub fn path_limit(&self, depth: usize) -> Result<usize, Error> {
        self.queries.checked_mul(depth).ok_or(Error::Overflow)
    }
    pub fn minimum_bytes(&self) -> Result<usize, Error> {
        let add = |a: usize, b: usize| a.checked_add(b).ok_or(Error::Overflow);
        let mul = |a: usize, b: usize| a.checked_mul(b).ok_or(Error::Overflow);
        let c = self.chunks;
        // Main+fixed local/next, quotient components, randomizer, helper OOD claims.
        let j = add(
            add(
                mul(2, add(self.main_width, self.fixed_width)?)?,
                mul(c, 10)?,
            )?,
            20,
        )?;
        let row = add(
            add(self.main_width, self.fixed_width)?,
            add(15, mul(c, 10)?)?,
        )?;
        let matrices = add(c, 3)?;
        let per_query = add(
            add(mul(row, 8)?, mul(matrices, 64)?)?,
            mul(self.folds(), 104)?,
        )?;
        let roots = mul(add(3, self.folds())?, 64)?;
        // Thirteen (for H1024) canonical zero PoW witnesses, including outer OOD.
        let pow = mul(add(3, self.folds())?, 8)?;
        let path_counts = mul(add(4, self.folds())?, 4)?;
        add(
            add(add(mul(j, 40)?, mul(self.queries, per_query)?)?, roots)?,
            add(add(pow, 44)?, path_counts)?,
        )
    }
}
