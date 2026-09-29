//! Transposition ciphers: Rail Fence, Columnar, and Route (spiral).
//!
//! Unlike the substitution modules, transposition rearranges letters without
//! changing them, so the conventional implementation operates on letters only
//! (non-letters are dropped and counted). Each transformed letter carries its
//! original case with it, so with [`CaseOptions::preserve_case`] set every
//! round-trip is exact for letter-only inputs; padding letters are uppercase.
//!
//! Errors are typed: degenerate shapes (fewer than 2 rails, zero columns,
//! keys that are not permutations, ciphertext that does not fit a pinned
//! grid) fail with expected/actual evidence.

use super::simple::CaseOptions;
use super::{check_text, TextResult, MAX_TEXT_BYTES, MAX_TRANSPOSITION_SHAPE};
use cybercipher_core::error::OperationError;

/// A letter plus the case it had in the input, so permutations can carry both.
type Letter = (u8, bool);

/// Uppercased letters of `text` with their original-case flags.
fn letters_of(text: &str) -> Vec<Letter> {
    text.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| (c.to_ascii_uppercase() as u8, c.is_ascii_lowercase()))
        .collect()
}

fn render(letters: &[Letter], preserve_case: bool) -> String {
    letters
        .iter()
        .map(|&(b, lower)| {
            let c = b as char;
            if preserve_case && lower {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect()
}

fn ok(letters: &[Letter], preserve_case: bool, input_letters: usize) -> TextResult {
    TextResult {
        output: render(letters, preserve_case),
        letters: input_letters,
        passthrough: 0,
    }
}

// ---------------------------------------------------------- Rail Fence ----

/// Options for [`rail_fence_encode`] / [`rail_fence_decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RailFenceOptions {
    /// Number of zigzag rails, 2..=[`MAX_TRANSPOSITION_SHAPE`]. Default: 3.
    pub rails: usize,
    /// Start `offset` positions into the zigzag cycle. Default: 0.
    pub offset: usize,
    /// Case handling. Default: preserve.
    pub case: CaseOptions,
}

impl Default for RailFenceOptions {
    fn default() -> Self {
        Self {
            rails: 3,
            offset: 0,
            case: CaseOptions::default(),
        }
    }
}

/// The rail index of each position: `0,1,..,r-1,r-2,..,1` repeating, starting
/// `offset` steps into the cycle.
fn rail_pattern(len: usize, rails: usize, offset: usize) -> Vec<usize> {
    let cycle = 2 * rails - 2;
    let start = offset % cycle;
    (0..len)
        .map(|i| {
            let step = (start + i) % cycle;
            if step < rails {
                step
            } else {
                cycle - step
            }
        })
        .collect()
}

fn validate_rails(rails: usize) -> Result<(), OperationError> {
    if rails < 2 || rails > MAX_TRANSPOSITION_SHAPE {
        return Err(OperationError::invalid_param(
            "rails",
            format!("rails must be in 2..={MAX_TRANSPOSITION_SHAPE}"),
        )
        .with_expected(format!("2..={MAX_TRANSPOSITION_SHAPE}"))
        .with_actual(rails.to_string()));
    }
    Ok(())
}

/// Rail-fence-encode `text`: write letters in a zigzag across `rails` rails
/// (starting `offset` steps into the cycle) and read the rails top to bottom.
pub fn rail_fence_encode(
    text: &str,
    options: &RailFenceOptions,
) -> Result<TextResult, OperationError> {
    check_text(text)?;
    validate_rails(options.rails)?;
    let letters = letters_of(text);
    let pattern = rail_pattern(letters.len(), options.rails, options.offset);
    let mut rails: Vec<Vec<Letter>> = vec![Vec::new(); options.rails];
    for (letter, rail) in letters.iter().zip(&pattern) {
        rails[*rail].push(*letter);
    }
    let flat: Vec<Letter> = rails.into_iter().flatten().collect();
    Ok(ok(&flat, options.case.preserve_case, letters.len()))
}

/// Rail-fence-decode `text`: rebuild the zigzag pattern, slice the ciphertext
/// back onto rails by length, and read it off in zigzag order.
pub fn rail_fence_decode(
    text: &str,
    options: &RailFenceOptions,
) -> Result<TextResult, OperationError> {
    check_text(text)?;
    validate_rails(options.rails)?;
    let cipher = letters_of(text);
    let pattern = rail_pattern(cipher.len(), options.rails, options.offset);
    let mut rail_lens = vec![0usize; options.rails];
    for &rail in &pattern {
        rail_lens[rail] += 1;
    }
    let mut rail_idx = vec![0usize; options.rails];
    let mut rail_slices: Vec<&[Letter]> = Vec::with_capacity(options.rails);
    let mut rest: &[Letter] = &cipher;
    for &len in &rail_lens {
        let (head, tail) = rest.split_at(len.min(rest.len()));
        rail_slices.push(head);
        rest = tail;
    }
    let plain: Vec<Letter> = pattern
        .iter()
        .map(|&rail| {
            let idx = rail_idx[rail];
            rail_idx[rail] += 1;
            rail_slices[rail][idx]
        })
        .collect();
    Ok(ok(&plain, options.case.preserve_case, cipher.len()))
}

// ------------------------------------------------------------ Columnar ----

/// Options for [`columnar_encode`] / [`columnar_decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnarOptions {
    /// Numeric key: `key[i]` is the 1-based read order of column `i`, so the
    /// key must be a permutation of `1..=n` for an `n`-column grid.
    /// Example: `[3, 1, 4, 5, 2]` reads column 3 (0-based index 1)... i.e. the
    /// column holding the second letter is read first.
    pub key: Vec<u32>,
    /// When set, pad the final row to a full rectangle with this character
    /// (typically `'X'`); when `None` the last row is ragged and short
    /// columns are simply shorter. Default: `None`.
    pub padding: Option<char>,
    /// Case handling. Default: preserve.
    pub case: CaseOptions,
}

impl Default for ColumnarOptions {
    fn default() -> Self {
        Self {
            key: vec![3, 1, 4, 5, 2],
            padding: None,
            case: CaseOptions::default(),
        }
    }
}

/// Validate the numeric key: a non-empty permutation of 1..=n within bounds.
fn validate_columnar_key(key: &[u32]) -> Result<usize, OperationError> {
    let n = key.len();
    if n == 0 || n > MAX_TRANSPOSITION_SHAPE {
        return Err(OperationError::invalid_param(
            "key",
            format!("columnar key length must be in 1..={MAX_TRANSPOSITION_SHAPE}"),
        )
        .with_expected(format!("1..={MAX_TRANSPOSITION_SHAPE} columns"))
        .with_actual(n.to_string()));
    }
    let mut seen = vec![false; n + 1];
    for &v in key {
        let v = v as usize;
        if v == 0 || v > n {
            return Err(OperationError::invalid_param(
                "key",
                "columnar key must be a permutation of 1..=n",
            )
            .with_expected(format!("a permutation of 1..={n}"))
            .with_actual(format!("{v}")));
        }
        if seen[v] {
            return Err(OperationError::invalid_param(
                "key",
                "columnar key must not repeat a column order",
            )
            .with_expected(format!("a permutation of 1..={n}"))
            .with_actual(format!("{v} appears twice")));
        }
        seen[v] = true;
    }
    Ok(n)
}

/// Columnar-transpose-encode `text`: write letters row-wise under `n`
/// columns, then read whole columns in the order given by the numeric key.
/// With [`ColumnarOptions::padding`] set, the text is padded to a full
/// rectangle first.
pub fn columnar_encode(
    text: &str,
    options: &ColumnarOptions,
) -> Result<TextResult, OperationError> {
    check_text(text)?;
    let n = validate_columnar_key(&options.key)?;
    let mut letters = letters_of(text);
    let input_letters = letters.len();
    if let Some(pad) = options.padding {
        let remainder = letters.len() % n;
        if remainder != 0 {
            letters.extend(std::iter::repeat((pad.to_ascii_uppercase() as u8, false)).take(n - remainder));
        }
    }
    let total = letters.len();
    let mut out = Vec::with_capacity(total);
    for order in 1..=n as u32 {
        let col = options
            .key
            .iter()
            .position(|&k| k == order)
            .expect("validated permutation");
        let mut idx = col;
        while idx < total {
            out.push(letters[idx]);
            idx += n;
        }
    }
    Ok(ok(&out, options.case.preserve_case, input_letters))
}

/// Columnar-transpose-decode `text`: invert the key-ordered column read.
/// With padding enabled the returned plaintext includes the pad letters.
pub fn columnar_decode(
    text: &str,
    options: &ColumnarOptions,
) -> Result<TextResult, OperationError> {
    check_text(text)?;
    let n = validate_columnar_key(&options.key)?;
    let cipher = letters_of(text);
    let total = cipher.len();
    // Column heights: column i (original position) holds ceil((total - i)/n)
    // letters when the text is written row-wise.
    let mut heights = vec![0usize; n];
    for (i, h) in heights.iter_mut().enumerate() {
        *h = (total + n - 1 - i) / n;
    }
    // Walk the ciphertext in key order, slicing each column's share.
    let mut columns: Vec<Vec<Letter>> = vec![Vec::new(); n];
    let mut offset = 0usize;
    for order in 1..=n as u32 {
        let col = options
            .key
            .iter()
            .position(|&k| k == order)
            .expect("validated permutation");
        let len = heights[col];
        columns[col] = cipher[offset..offset + len].to_vec();
        offset += len;
    }
    // Read row-wise.
    let mut idxs = vec![0usize; n];
    let mut plain: Vec<Letter> = Vec::with_capacity(total);
    'rows: for _ in 0..n {
        for col in 0..n {
            if idxs[col] < heights[col] {
                plain.push(columns[col][idxs[col]]);
                idxs[col] += 1;
                if plain.len() == total {
                    break 'rows;
                }
            }
        }
    }
    Ok(ok(&plain, options.case.preserve_case, total))
}

// --------------------------------------------------------------- Route ----

/// Options for [`route_encode`] / [`route_decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteOptions {
    /// Grid width in columns, 1..=[`MAX_TRANSPOSITION_SHAPE`]. The row count
    /// is derived (see [`RouteOptions::rows`]). Default: 5.
    pub columns: usize,
    /// Optional explicit row count. When set the text is padded to a full
    /// `rows × columns` rectangle with [`RouteOptions::filler`]; when `None`
    /// the row count is the minimum that fits the text. Default: `None`.
    pub rows: Option<usize>,
    /// Filler character for padding to a full rectangle. Default: `'X'`.
    pub filler: char,
    /// Case handling. Default: preserve.
    pub case: CaseOptions,
}

impl Default for RouteOptions {
    fn default() -> Self {
        Self {
            columns: 5,
            rows: None,
            filler: 'X',
            case: CaseOptions::default(),
        }
    }
}

/// Spiral visit order (clockwise inward, starting top-left going right) over
/// a `rows × columns` grid, as flat row-major indices.
fn spiral_order(rows: usize, columns: usize) -> Vec<usize> {
    let mut order = Vec::with_capacity(rows * columns);
    let (mut top, mut bottom) = (0usize, rows.saturating_sub(1));
    let (mut left, mut right) = (0usize, columns.saturating_sub(1));
    while top <= bottom && left <= right {
        for c in left..=right {
            order.push(top * columns + c);
        }
        if top == bottom {
            break;
        }
        for r in top + 1..=bottom {
            order.push(r * columns + right);
        }
        if left == right {
            break;
        }
        for c in (left..right).rev() {
            order.push(bottom * columns + c);
        }
        for r in (top + 1..bottom).rev() {
            order.push(r * columns + left);
        }
        top += 1;
        bottom = bottom.saturating_sub(1);
        left += 1;
        right = right.saturating_sub(1);
    }
    order
}

fn validate_route_shape(columns: usize, rows: Option<usize>) -> Result<(), OperationError> {
    if columns == 0 || columns > MAX_TRANSPOSITION_SHAPE {
        return Err(OperationError::invalid_param(
            "columns",
            format!("columns must be in 1..={MAX_TRANSPOSITION_SHAPE}"),
        )
        .with_expected(format!("1..={MAX_TRANSPOSITION_SHAPE}"))
        .with_actual(columns.to_string()));
    }
    if let Some(rows) = rows {
        if rows == 0 || rows > MAX_TRANSPOSITION_SHAPE {
            return Err(OperationError::invalid_param(
                "rows",
                format!("rows must be in 1..={MAX_TRANSPOSITION_SHAPE}"),
            )
            .with_expected(format!("1..={MAX_TRANSPOSITION_SHAPE}"))
            .with_actual(rows.to_string()));
        }
    }
    Ok(())
}

/// Route-encode `text`: fill a `rows × columns` grid row-wise and read it off
/// in a clockwise inward spiral starting at the top-left corner.
pub fn route_encode(text: &str, options: &RouteOptions) -> Result<TextResult, OperationError> {
    check_text(text)?;
    validate_route_shape(options.columns, options.rows)?;
    let mut letters = letters_of(text);
    let input_letters = letters.len();
    let rows = match options.rows {
        Some(r) => r,
        None => letters.len().div_ceil(options.columns).max(1),
    };
    let capacity = rows * options.columns;
    if capacity > MAX_TEXT_BYTES {
        return Err(OperationError::invalid_param(
            "columns",
            "the requested grid exceeds the input bound",
        )
        .with_expected(format!("at most {MAX_TEXT_BYTES} cells"))
        .with_actual(format!("{capacity} cells")));
    }
    let filler = (options.filler.to_ascii_uppercase() as u8, false);
    letters.resize(capacity, filler);
    let order = spiral_order(rows, options.columns);
    let out: Vec<Letter> = order.iter().map(|&cell| letters[cell]).collect();
    Ok(ok(&out, options.case.preserve_case, input_letters))
}

/// Route-decode `text`: undo the spiral read. Padding letters (if any) are
/// part of the returned plaintext.
pub fn route_decode(text: &str, options: &RouteOptions) -> Result<TextResult, OperationError> {
    check_text(text)?;
    validate_route_shape(options.columns, options.rows)?;
    let cipher = letters_of(text);
    let rows = match options.rows {
        Some(r) => r,
        None => cipher.len().div_ceil(options.columns).max(1),
    };
    let capacity = rows * options.columns;
    if cipher.len() > capacity {
        return Err(OperationError::length(
            format!("at most {capacity} letters for a {rows}x{} grid", options.columns),
            format!("{} letters", cipher.len()),
            "ciphertext does not fit the requested grid",
        ));
    }
    let mut grid: Vec<Letter> = vec![(b'X', false); capacity];
    let order = spiral_order(rows, options.columns);
    for (i, &cell) in order.iter().enumerate() {
        grid[cell] = cipher[i];
    }
    Ok(ok(&grid, options.case.preserve_case, cipher.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPT: RailFenceOptions = RailFenceOptions {
        rails: 3,
        offset: 0,
        case: CaseOptions { preserve_case: true },
    };

    #[test]
    fn rail_fence_classic_vector() {
        let text = "WEAREDISCOVEREDFLEEATONCE";
        let enc = rail_fence_encode(text, &OPT).unwrap();
        assert_eq!(enc.output, "WECRLTEERDSOEEFEAOCAIVDEN");
        assert_eq!(rail_fence_decode(&enc.output, &OPT).unwrap().output, text);
    }

    #[test]
    fn rail_fence_offset_rotates_pattern() {
        let opt = RailFenceOptions {
            rails: 3,
            offset: 1,
            ..RailFenceOptions::default()
        };
        // Cycle 1,2,1,0 repeating: rails r0=[D], r1=[A,C,E], r2=[B,F].
        let enc = rail_fence_encode("ABCDEF", &opt).unwrap();
        assert_eq!(enc.output, "DACEBF");
        assert_eq!(rail_fence_decode(&enc.output, &opt).unwrap().output, "ABCDEF");
    }

    #[test]
    fn rail_fence_two_rails_swaps_halves() {
        let opt = RailFenceOptions {
            rails: 2,
            offset: 0,
            ..RailFenceOptions::default()
        };
        let enc = rail_fence_encode("ABCDEFGH", &opt).unwrap();
        assert_eq!(enc.output, "ACEGBDFH");
        assert_eq!(rail_fence_decode(&enc.output, &opt).unwrap().output, "ABCDEFGH");
    }

    #[test]
    fn rail_fence_preserves_case_through_permutation() {
        let enc = rail_fence_encode("AbCdEf", &OPT).unwrap();
        // Letters A..F zigzag over 3 rails: r0=[A,E], r1=[B,D,F], r2=[C];
        // each letter carries its own case, so B, D and F render lowercase.
        assert_eq!(enc.output, "AEbdfC");
        let dec = rail_fence_decode(&enc.output, &OPT).unwrap().output;
        assert_eq!(dec, "AbCdEf");
    }

    #[test]
    fn rail_fence_rejects_degenerate_rails() {
        assert!(rail_fence_encode("abc", &RailFenceOptions { rails: 1, ..OPT }).is_err());
        assert!(rail_fence_decode("abc", &RailFenceOptions { rails: 0, ..OPT }).is_err());
        let err = rail_fence_encode("abc", &RailFenceOptions { rails: 1, ..OPT }).unwrap_err();
        assert_eq!(err.expected.as_deref(), Some("2..=4096"));
        assert_eq!(err.actual.as_deref(), Some("1"));
    }

    #[test]
    fn columnar_known_layout() {
        let opt = ColumnarOptions {
            key: vec![3, 1, 4, 5, 2],
            padding: None,
            case: CaseOptions { preserve_case: true },
        };
        // 12 letters / 5 columns: rows ATTAC | KATDA | WN.
        // col0: A K W; col1: T A N; col2: T T; col3: A D; col4: C A.
        // key [3,1,4,5,2]: col0 read 3rd, col1 1st, col2 4th, col3 5th,
        // col4 2nd → TAN CA AKW TT AD.
        let text = "ATTACKATDAWN";
        let enc = columnar_encode(text, &opt).unwrap();
        assert_eq!(enc.output, "TANCAAKWTTAD");
        assert_eq!(columnar_decode(&enc.output, &opt).unwrap().output, text);
    }

    #[test]
    fn columnar_with_padding_round_trips() {
        let opt = ColumnarOptions {
            key: vec![2, 1],
            padding: Some('X'),
            case: CaseOptions { preserve_case: true },
        };
        // Rows AB | CX: col0=[A,C], col1=[B,X]; read order 1→col1, 2→col0.
        let enc = columnar_encode("ABC", &opt).unwrap();
        assert_eq!(enc.output, "BXAC");
        let dec = columnar_decode(&enc.output, &opt).unwrap().output;
        assert_eq!(dec, "ABCX");
    }

    #[test]
    fn columnar_rejects_non_permutations() {
        let opt = ColumnarOptions {
            key: vec![1, 1],
            padding: None,
            case: CaseOptions::default(),
        };
        let err = columnar_encode("AB", &opt).unwrap_err();
        assert!(err.actual.as_deref().unwrap().contains("twice"));
        let opt = ColumnarOptions {
            key: vec![1, 3],
            padding: None,
            case: CaseOptions::default(),
        };
        assert!(columnar_encode("AB", &opt).is_err());
        let opt = ColumnarOptions {
            key: vec![],
            padding: None,
            case: CaseOptions::default(),
        };
        assert!(columnar_encode("AB", &opt).is_err());
    }

    #[test]
    fn route_spiral_known_layout() {
        // 3x3 grid of ABCDEFGHI read clockwise from the top-left:
        // cells 0,1,2,5,8,7,6,3,4 → A B C F I H G D E.
        let opt = RouteOptions {
            columns: 3,
            rows: Some(3),
            filler: 'X',
            case: CaseOptions { preserve_case: true },
        };
        let enc = route_encode("ABCDEFGHI", &opt).unwrap();
        assert_eq!(enc.output, "ABCFIHGDE");
        assert_eq!(route_decode(&enc.output, &opt).unwrap().output, "ABCDEFGHI");
    }

    #[test]
    fn route_round_trips_with_derived_rows() {
        let opt = RouteOptions::default(); // 5 columns, rows derived
        let text = "THEQUICKBROWNFOXJUMPSOVER"; // 25 letters = 5x5
        let enc = route_encode(text, &opt).unwrap();
        assert_eq!(route_decode(&enc.output, &opt).unwrap().output, text);
    }

    #[test]
    fn route_pads_when_rows_are_pinned() {
        let opt = RouteOptions {
            columns: 4,
            rows: Some(2),
            filler: 'X',
            case: CaseOptions { preserve_case: true },
        };
        // Spiral order over 2x4: 0,1,2,3,7,6,5,4 → A B C D X X F E.
        let enc = route_encode("ABCDEF", &opt).unwrap();
        assert_eq!(enc.output, "ABCDXXFE");
        let dec = route_decode(&enc.output, &opt).unwrap().output;
        assert_eq!(dec, "ABCDEFXX");
    }

    #[test]
    fn route_rejects_impossible_fit() {
        let opt = RouteOptions {
            columns: 4,
            rows: Some(2),
            filler: 'X',
            case: CaseOptions::default(),
        };
        assert!(route_decode("ABCDEFGHI", &opt).is_err());
        assert!(route_encode("A", &RouteOptions { columns: 0, ..opt }).is_err());
        assert!(route_encode("A", &RouteOptions { rows: Some(0), ..opt }).is_err());
    }

    #[test]
    fn transposition_preserves_letter_multiset() {
        // 25 letters: exactly fills the default 5-column route grid, so no
        // padding letters disturb the multiset comparison.
        let text = "THEQUICKBROWNFOXJUMPSOVER";
        let outputs = [
            rail_fence_encode(text, &OPT).unwrap().output,
            columnar_encode(
                text,
                &ColumnarOptions {
                    key: vec![4, 2, 1, 3],
                    padding: None,
                    case: CaseOptions::default(),
                },
            )
            .unwrap()
            .output,
            route_encode(text, &RouteOptions::default()).unwrap().output,
        ];
        for out in outputs {
            let mut a: Vec<char> = text.chars().collect();
            let mut b: Vec<char> = out.chars().collect();
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b, "transposition must preserve letters");
        }
    }

    #[test]
    fn oversized_input_rejected() {
        let big = "a".repeat(MAX_TEXT_BYTES + 1);
        assert!(rail_fence_encode(&big, &OPT).is_err());
        assert!(columnar_decode(&big, &ColumnarOptions::default()).is_err());
        assert!(route_encode(&big, &RouteOptions::default()).is_err());
    }
}
