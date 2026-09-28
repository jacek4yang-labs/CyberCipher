//! Integer lattice / integer matrix type shared by the LLL reducer and the
//! Coppersmith construction.
//!
//! A [`Lattice`] is a dense `n × m` matrix of [`BigInt`] whose rows are the
//! lattice basis vectors. Construction validates the resource caps declared
//! in [`crate::lattice`] (dimension and total bit budget) so a hostile input
//! is rejected with a typed error before any reduction work starts.
//!
//! Row operations (`swap_rows`, `add_row_multiple`, `mul_row_scalar`) are the
//! elementary unimodular moves LLL is built from; `determinant` (Bareiss
//! fraction-free elimination, exact for integer matrices) supports the
//! lattice-invariance checks used by the tests.

use super::{exact_div, MAX_COLS, MAX_DIM, MAX_TOTAL_BITS};
use cybercipher_core::error::{ErrorKind, OperationError};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use std::fmt;

/// An integer lattice: `n` basis rows living in `Z^m`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lattice {
    rows: Vec<Vec<BigInt>>,
}

impl Lattice {
    /// Build from basis rows. All rows must have the same, non-zero width
    /// and the matrix must respect the module caps.
    pub fn from_rows(rows: Vec<Vec<BigInt>>) -> Result<Self, OperationError> {
        if rows.is_empty() {
            return Err(OperationError::invalid_param(
                "rows",
                "lattice needs at least one row",
            ));
        }
        if rows.len() > MAX_DIM {
            return Err(OperationError::invalid_param(
                "rows",
                format!("lattice dimension {} exceeds cap {MAX_DIM}", rows.len()),
            )
            .with_expected(MAX_DIM.to_string())
            .with_actual(rows.len().to_string()));
        }
        let ncols = rows[0].len();
        if ncols == 0 {
            return Err(OperationError::invalid_param(
                "rows",
                "lattice rows must have at least one column",
            ));
        }
        if ncols > MAX_COLS {
            return Err(OperationError::invalid_param(
                "rows",
                format!("lattice has {ncols} columns, exceeding cap {MAX_COLS}"),
            )
            .with_expected(MAX_COLS.to_string())
            .with_actual(ncols.to_string()));
        }
        let mut total_bits = 0u64;
        for (i, row) in rows.iter().enumerate() {
            if row.len() != ncols {
                return Err(OperationError::invalid_param(
                    "rows",
                    format!("row {i} has width {}, expected {ncols}", row.len()),
                ));
            }
            for c in row {
                total_bits += c.bits();
            }
        }
        if total_bits > MAX_TOTAL_BITS {
            return Err(OperationError::new(
                ErrorKind::BudgetExceeded,
                format!(
                    "lattice entries total {total_bits} bits, exceeding budget {MAX_TOTAL_BITS}"
                ),
            )
            .with_expected(MAX_TOTAL_BITS.to_string())
            .with_actual(total_bits.to_string())
            .with_parameter("rows"));
        }
        Ok(Lattice { rows })
    }

    /// Build from non-negative [`BigUint`] rows.
    pub fn from_biguint_rows(rows: &[Vec<BigUint>]) -> Result<Self, OperationError> {
        let converted: Vec<Vec<BigInt>> = rows
            .iter()
            .map(|r| r.iter().map(|c| BigInt::from(c.clone())).collect())
            .collect();
        Self::from_rows(converted)
    }

    /// The `n × n` identity matrix.
    pub fn identity(n: usize) -> Result<Self, OperationError> {
        if n > MAX_DIM {
            return Err(OperationError::invalid_param(
                "n",
                format!("identity of order {n} exceeds cap {MAX_DIM}"),
            ));
        }
        let one = BigInt::from(1);
        let zero = BigInt::from(0);
        let rows = (0..n)
            .map(|i| {
                (0..n)
                    .map(|j| if i == j { one.clone() } else { zero.clone() })
                    .collect()
            })
            .collect();
        Lattice::from_rows(rows)
    }

    /// Number of basis rows.
    pub fn nrows(&self) -> usize {
        self.rows.len()
    }

    /// Ambient dimension (columns).
    pub fn ncols(&self) -> usize {
        self.rows.first().map_or(0, |r| r.len())
    }

    /// `(nrows, ncols)`.
    pub fn dims(&self) -> (usize, usize) {
        (self.nrows(), self.ncols())
    }

    /// Borrowed basis rows.
    pub fn rows(&self) -> &[Vec<BigInt>] {
        &self.rows
    }

    /// Borrowed row `i`.
    pub fn row(&self, i: usize) -> &[BigInt] {
        &self.rows[i]
    }

    /// Square of the Euclidean norm of row `i` (exact integer).
    pub fn norm_squared(&self, i: usize) -> BigInt {
        self.rows[i]
            .iter()
            .fold(BigInt::zero(), |acc, c| acc + c * c)
    }

    /// Squared Euclidean norms of all rows.
    pub fn norms_squared(&self) -> Vec<BigInt> {
        (0..self.nrows()).map(|i| self.norm_squared(i)).collect()
    }

    /// Swap rows `i` and `j` (det multiplies by −1).
    pub fn swap_rows(&mut self, i: usize, j: usize) {
        self.rows.swap(i, j);
    }

    /// `row[target] += k * row[src]` (elementary unimodular move, det = ±1).
    pub fn add_row_multiple(&mut self, target: usize, src: usize, k: &BigInt) {
        if k.is_zero() || target == src {
            return;
        }
        let src_row = self.rows[src].clone();
        for (t, s) in self.rows[target].iter_mut().zip(src_row.iter()) {
            *t += k * s;
        }
    }

    /// `row[i] *= k`.
    pub fn mul_row_scalar(&mut self, i: usize, k: &BigInt) {
        for c in &mut self.rows[i] {
            *c *= k;
        }
    }

    /// Multiply an `n × n` transform `u` against this `n × m` matrix:
    /// result row `i` = `Σ_j u[i][j] * row(j)`. Used to verify that a
    /// reduced basis is an integer row-combination of the original.
    pub fn transform_rows(&self, u: &Lattice) -> Result<Self, OperationError> {
        let (n, m) = self.dims();
        if u.dims() != (n, n) {
            return Err(OperationError::invalid_param(
                "u",
                format!("transform must be {n}x{n}, got {:?}", u.dims()),
            ));
        }
        let zero = BigInt::from(0);
        let rows = (0..n)
            .map(|i| {
                let mut acc = vec![zero.clone(); m];
                for (j, uij) in u.row(i).iter().enumerate() {
                    if !uij.is_zero() {
                        for (a, b) in acc.iter_mut().zip(self.row(j).iter()) {
                            *a += uij * b;
                        }
                    }
                }
                acc
            })
            .collect();
        Lattice::from_rows(rows)
    }

    /// Determinant of a square matrix via Bareiss fraction-free elimination
    /// (exact for integer matrices: every division is provably exact).
    /// Non-square input is an `InvalidParam` error.
    pub fn determinant(&self) -> Result<BigInt, OperationError> {
        let (n, m) = self.dims();
        if n != m {
            return Err(OperationError::invalid_param(
                "determinant",
                format!("determinant needs a square matrix, got {n}x{m}"),
            ));
        }
        if n == 0 {
            return Ok(BigInt::from(1));
        }
        let mut a = self.rows.clone();
        let mut sign = BigInt::from(1);
        let mut prev = BigInt::from(1);
        for k in 0..n {
            if a[k][k].is_zero() {
                let pivot = (k + 1..n).find(|&i| !a[i][k].is_zero());
                let Some(p) = pivot else {
                    return Ok(BigInt::from(0));
                };
                a.swap(k, p);
                sign = -sign;
            }
            for i in k + 1..n {
                for j in k + 1..n {
                    let num = &a[i][j] * &a[k][k] - &a[i][k] * &a[k][j];
                    a[i][j] = if k == 0 { num } else { exact_div(&num, &prev)? };
                }
                a[i][k] = BigInt::zero();
            }
            prev = a[k][k].clone();
        }
        Ok(sign * a[n - 1].last().unwrap())
    }
}

impl fmt::Display for Lattice {
    /// Rows with their exact squared Euclidean norms.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Lattice {}x{}", self.nrows(), self.ncols())?;
        for (i, row) in self.rows.iter().enumerate() {
            let coeffs: Vec<String> = row.iter().map(|c| c.to_string()).collect();
            writeln!(
                f,
                "  row {i}: [{}] |v|^2 = {}",
                coeffs.join(", "),
                self.norm_squared(i)
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(v: &[i64]) -> Vec<BigInt> {
        v.iter().map(|&x| BigInt::from(x)).collect()
    }

    #[test]
    fn construction_validates_shape() {
        assert!(Lattice::from_rows(vec![b(&[1, 2]), b(&[3])]).is_err());
        assert!(Lattice::from_rows(vec![b(&[1, 2]), b(&[3, 4]), b(&[5, 6]),]).is_ok());
        assert!(Lattice::from_rows(Vec::<Vec<BigInt>>::new()).is_err());
        // Zero rows are representable (LLL rejects them, not the matrix type).
        assert!(Lattice::from_rows(vec![b(&[0, 0])]).is_ok());
    }

    #[test]
    fn determinant_matches_hand_values() {
        let l = Lattice::from_rows(vec![b(&[1, 2]), b(&[3, 4])]).unwrap();
        assert_eq!(l.determinant().unwrap(), BigInt::from(-2));
        let l = Lattice::from_rows(vec![b(&[2, 0, 0]), b(&[0, 3, 0]), b(&[0, 0, 5])]).unwrap();
        assert_eq!(l.determinant().unwrap(), BigInt::from(30));
        // Needs a pivot swap; det = -(1 * det[[5,6],[8,9]] ) = -(45-48) = 3 with sign flips.
        let l = Lattice::from_rows(vec![b(&[0, 1]), b(&[1, 0])]).unwrap();
        assert_eq!(l.determinant().unwrap(), BigInt::from(-1));
        let l = Lattice::from_rows(vec![b(&[1, 2, 3]), b(&[4, 5, 6]), b(&[7, 8, 9])]).unwrap();
        assert_eq!(l.determinant().unwrap(), BigInt::from(0));
        let l = Lattice::from_rows(vec![b(&[7])]).unwrap();
        assert_eq!(l.determinant().unwrap(), BigInt::from(7));
    }

    #[test]
    fn determinant_is_exact_on_big_entries() {
        // Bareiss must stay exact where float Gaussian elimination would not.
        let big = BigInt::from(1u8) << 200u32;
        let l = Lattice::from_rows(vec![
            vec![big.clone(), BigInt::from(3)],
            vec![BigInt::from(5), big.clone()],
        ])
        .unwrap();
        let det = l.determinant().unwrap();
        assert_eq!(det, &big * &big - BigInt::from(15));
    }

    #[test]
    fn row_ops_behave() {
        let mut l = Lattice::from_rows(vec![b(&[1, 2]), b(&[3, 4])]).unwrap();
        l.add_row_multiple(1, 0, &BigInt::from(-3));
        assert_eq!(l.row(1), &b(&[0, -2]));
        l.mul_row_scalar(1, &BigInt::from(-1));
        assert_eq!(l.row(1), &b(&[0, 2]));
        l.swap_rows(0, 1);
        assert_eq!(l.row(0), &b(&[0, 2]));
        assert_eq!(l.row(1), &b(&[1, 2]));
        // No-op when k = 0.
        l.add_row_multiple(0, 1, &BigInt::from(0));
        assert_eq!(l.row(0), &b(&[0, 2]));
    }

    #[test]
    fn transform_rows_multiplies() {
        let l = Lattice::from_rows(vec![b(&[1, 2]), b(&[3, 4])]).unwrap();
        let u = Lattice::from_rows(vec![b(&[0, 1]), b(&[1, 0])]).unwrap();
        let r = l.transform_rows(&u).unwrap();
        assert_eq!(r.row(0), &b(&[3, 4]));
        assert_eq!(r.row(1), &b(&[1, 2]));
    }

    #[test]
    fn norms_and_display() {
        let l = Lattice::from_rows(vec![b(&[3, 4]), b(&[1, 0])]).unwrap();
        assert_eq!(l.norm_squared(0), BigInt::from(25));
        assert_eq!(l.norms_squared(), vec![BigInt::from(25), BigInt::from(1)]);
        let s = l.to_string();
        assert!(s.contains("Lattice 2x2"));
        assert!(s.contains("|v|^2 = 25"));
    }
}
