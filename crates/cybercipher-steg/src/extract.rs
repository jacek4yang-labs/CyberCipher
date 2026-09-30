//! Bit extraction — a bit-exact port of the StegSolver `DataExtractor`
//! conventions (reference commit `c14bfa9`).
//!
//! Contract (do not silently change any of it; parity walkthroughs depend on
//! it):
//!
//! * visit order per pixel: **alpha first**, then the colour channels in the
//!   configured [`RgbOrder`];
//! * inside a channel, bit planes are visited **7 down to 0** for MSB-first
//!   extraction and **0 up to 7** for LSB-first extraction;
//! * extracted bits are appended **most significant bit first**, so the
//!   first bit read becomes bit 7 of the first output byte;
//! * a trailing partial byte is **zero padded**;
//! * `invert_bits` complements the whole pixel before reading;
//! * traversal is row-first or column-first over the clamped ROI;
//! * bounded extraction reports `total_bytes` (what a full run would
//!   produce) and `truncated`.

use cybercipher_core::{ExecutionContext, OpResult, OperationError};
use cybercipher_media::{RgbaImage, Roi};

/// The order in which the colour channels are visited while extracting,
/// matching the six permutations the legacy tool offered. Alpha is always
/// visited first regardless of this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RgbOrder {
    Rgb,
    Rbg,
    Grb,
    Gbr,
    Brg,
    Bgr,
}

impl RgbOrder {
    /// The colour channels in visit order, excluding alpha.
    #[must_use]
    pub fn colours(self) -> [crate::transforms::Channel; 3] {
        use crate::transforms::Channel::{Blue, Green, Red};
        match self {
            RgbOrder::Rgb => [Red, Green, Blue],
            RgbOrder::Rbg => [Red, Blue, Green],
            RgbOrder::Grb => [Green, Red, Blue],
            RgbOrder::Gbr => [Green, Blue, Red],
            RgbOrder::Brg => [Blue, Red, Green],
            RgbOrder::Bgr => [Blue, Green, Red],
        }
    }

    /// Full visit order: alpha followed by the colour channels.
    #[must_use]
    pub fn visit_order(self) -> [crate::transforms::Channel; 4] {
        [
            crate::transforms::Channel::Alpha,
            self.colours()[0],
            self.colours()[1],
            self.colours()[2],
        ]
    }

    /// The legacy `rgbOrder` numbering (1 = RGB .. 6 = BGR).
    #[must_use]
    pub fn legacy_code(self) -> u32 {
        match self {
            RgbOrder::Rgb => 1,
            RgbOrder::Rbg => 2,
            RgbOrder::Grb => 3,
            RgbOrder::Gbr => 4,
            RgbOrder::Brg => 5,
            RgbOrder::Bgr => 6,
        }
    }

    /// Parses the legacy code.
    ///
    /// # Errors
    ///
    /// Fails with [`OperationError`] for codes outside 1..=6.
    pub fn from_legacy_code(code: u32) -> OpResult<Self> {
        match code {
            1 => Ok(RgbOrder::Rgb),
            2 => Ok(RgbOrder::Rbg),
            3 => Ok(RgbOrder::Grb),
            4 => Ok(RgbOrder::Gbr),
            5 => Ok(RgbOrder::Brg),
            6 => Ok(RgbOrder::Bgr),
            other => Err(OperationError::invalid_param(
                "order",
                format!("unknown RGB order code {other}"),
            )
            .with_expected("1..=6")
            .with_actual(other.to_string())),
        }
    }
}

/// The options of a data extraction run.
///
/// The selection is a 32-bit mask in "plane space": bit
/// `channel_ordinal * 8 + plane` is set when that bit plane is extracted.
/// [`ExtractionOptions::argb_mask`] reproduces the ARGB mask the legacy UI
/// showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionOptions {
    pub plane_mask: u32,
    pub order: RgbOrder,
    pub lsb_first: bool,
    pub row_first: bool,
    pub invert_bits: bool,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        // The common CTF default: LSB of red, green and blue.
        Self::none()
            .with_plane(crate::transforms::Channel::Red, 0, true)
            .with_plane(crate::transforms::Channel::Green, 0, true)
            .with_plane(crate::transforms::Channel::Blue, 0, true)
    }
}

impl ExtractionOptions {
    /// Nothing selected, which produces an empty extract.
    #[must_use]
    pub fn none() -> Self {
        Self {
            plane_mask: 0,
            order: RgbOrder::Rgb,
            lsb_first: false,
            row_first: true,
            invert_bits: false,
        }
    }

    /// Every bit plane of every channel.
    #[must_use]
    pub fn all_planes() -> Self {
        Self {
            plane_mask: u32::MAX,
            ..Self::none()
        }
    }

    /// Bit position in plane space for a channel/plane pair.
    #[must_use]
    pub fn bit_for(channel: crate::transforms::Channel, plane: u32) -> u32 {
        debug_assert!(plane < 8);
        1 << (channel.ordinal() * 8 + plane)
    }

    #[must_use]
    pub fn is_selected(&self, channel: crate::transforms::Channel, plane: u32) -> bool {
        self.plane_mask & Self::bit_for(channel, plane) != 0
    }

    /// Selects or clears a single bit plane.
    #[must_use]
    pub fn with_plane(
        mut self,
        channel: crate::transforms::Channel,
        plane: u32,
        selected: bool,
    ) -> Self {
        let bit = Self::bit_for(channel, plane);
        self.plane_mask = if selected {
            self.plane_mask | bit
        } else {
            self.plane_mask & !bit
        };
        self
    }

    /// Selects or clears all eight bit planes of a channel.
    #[must_use]
    pub fn with_channel(mut self, channel: crate::transforms::Channel, selected: bool) -> Self {
        let mask = 0xFFu32 << (channel.ordinal() * 8);
        self.plane_mask = if selected {
            self.plane_mask | mask
        } else {
            self.plane_mask & !mask
        };
        self
    }

    /// Selects or clears one bit plane across all four channels.
    #[must_use]
    pub fn with_plane_across_channels(mut self, plane: u32, selected: bool) -> Self {
        use crate::transforms::Channel;
        for channel in [Channel::Alpha, Channel::Red, Channel::Green, Channel::Blue] {
            self = self.with_plane(channel, plane, selected);
        }
        self
    }

    #[must_use]
    pub fn with_order(mut self, order: RgbOrder) -> Self {
        self.order = order;
        self
    }

    #[must_use]
    pub fn with_lsb_first(mut self, value: bool) -> Self {
        self.lsb_first = value;
        self
    }

    #[must_use]
    pub fn with_row_first(mut self, value: bool) -> Self {
        self.row_first = value;
        self
    }

    #[must_use]
    pub fn with_invert_bits(mut self, value: bool) -> Self {
        self.invert_bits = value;
        self
    }

    /// Number of selected bit planes, 0..=32.
    #[must_use]
    pub fn selected_count(self) -> u32 {
        self.plane_mask.count_ones()
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.plane_mask == 0
    }

    /// The mask the legacy UI displayed: one ARGB bit per selected plane,
    /// alpha occupying bits 24..31 (alpha plane 7 is bit 31).
    #[must_use]
    pub fn argb_mask(self) -> u32 {
        use crate::transforms::Channel;
        let mut mask = 0;
        for channel in [Channel::Alpha, Channel::Red, Channel::Green, Channel::Blue] {
            for plane in 0..8 {
                if self.is_selected(channel, plane) {
                    mask |= 1 << (channel.shift() + plane);
                }
            }
        }
        mask
    }

    /// Status text such as `a7 r0 g0 b0` (plane order 7..0 per channel).
    #[must_use]
    pub fn describe(self) -> String {
        use crate::transforms::Channel;
        let mut text = String::new();
        for channel in [Channel::Alpha, Channel::Red, Channel::Green, Channel::Blue] {
            for plane in (0..8).rev() {
                if self.is_selected(channel, plane) {
                    if !text.is_empty() {
                        text.push(' ');
                    }
                    text.push(channel.symbol());
                    text.push(std::char::from_digit(plane, 10).unwrap_or('?'));
                }
            }
        }
        if text.is_empty() {
            "(no bit planes selected)".to_owned()
        } else {
            text
        }
    }

    /// Number of bytes `pixel_count` pixels produce with this selection.
    #[must_use]
    pub fn output_bytes_for(self, pixel_count: u64) -> u64 {
        let bits = pixel_count * u64::from(self.selected_count());
        bits.div_ceil(8)
    }
}

/// The outcome of a (possibly bounded) extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractResult {
    /// Extracted bytes, at most `max_bytes`.
    pub data: Vec<u8>,
    /// Number of bytes the full extraction would produce.
    pub total_bytes: u64,
    /// True when `data` is shorter than `total_bytes`.
    pub truncated: bool,
}

/// Extracts a bit stream out of an image region, at most `max_bytes` bytes.
///
/// Cancellation is checked once per row (row-first) or per column
/// (column-first), matching the reference's interrupt points.
///
/// # Errors
///
/// Fails with [`OperationError`] on cancellation. Malformed options are
/// rejected eagerly where they can be.
pub fn extract_bounded(
    image: &RgbaImage,
    region: Roi,
    options: ExtractionOptions,
    max_bytes: usize,
    ctx: &ExecutionContext,
) -> OpResult<ExtractResult> {
    let area = region.clamp_to(image.width, image.height);
    if area.is_empty() || options.is_empty() || max_bytes == 0 {
        let total = if area.is_empty() {
            0
        } else {
            options.output_bytes_for(area.area())
        };
        return Ok(ExtractResult {
            data: Vec::new(),
            total_bytes: total,
            truncated: total > 0,
        });
    }
    let total_bytes = options.output_bytes_for(area.area());
    let wanted = usize::try_from(total_bytes.min(max_bytes as u64)).unwrap_or(max_bytes);

    let plan = build_plan(&options);
    let pixels = &image.argb;
    let image_width = image.width as usize;
    let mut sink = BitSink::new(wanted);
    let invert = options.invert_bits;

    if options.row_first {
        for y in area.y..area.max_y() {
            ctx.check()?;
            let row_start = y as usize * image_width;
            for x in area.x..area.max_x() {
                if sink.is_full() {
                    return Ok(finish(sink, total_bytes));
                }
                sink.put_pixel(pixels[row_start + x as usize], &plan, invert);
            }
        }
    } else {
        for x in area.x..area.max_x() {
            ctx.check()?;
            for y in area.y..area.max_y() {
                if sink.is_full() {
                    return Ok(finish(sink, total_bytes));
                }
                sink.put_pixel(pixels[y as usize * image_width + x as usize], &plan, invert);
            }
        }
    }
    Ok(finish(sink, total_bytes))
}

fn finish(sink: BitSink, total_bytes: u64) -> ExtractResult {
    let data = sink.finish();
    let truncated = (data.len() as u64) < total_bytes;
    ExtractResult {
        data,
        total_bytes,
        truncated,
    }
}

/// Builds the extraction plan: the ARGB bit positions to read per pixel,
/// already in visit order.
fn build_plan(options: &ExtractionOptions) -> Vec<u32> {
    let mut plan = Vec::with_capacity(options.selected_count() as usize);
    for channel in options.order.visit_order() {
        if options.lsb_first {
            for plane in 0..8u32 {
                if options.is_selected(channel, plane) {
                    plan.push(channel.shift() + plane);
                }
            }
        } else {
            for plane in (0..8u32).rev() {
                if options.is_selected(channel, plane) {
                    plan.push(channel.shift() + plane);
                }
            }
        }
    }
    plan
}

/// Packs single bits into bytes, most significant bit first.
struct BitSink {
    out: Vec<u8>,
    byte_pos: usize,
    pending_bits: u64,
    bit_count: u32,
}

impl BitSink {
    fn new(capacity: usize) -> Self {
        Self {
            out: vec![0u8; capacity],
            byte_pos: 0,
            pending_bits: 0,
            bit_count: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.byte_pos >= self.out.len()
    }

    fn put_pixel(&mut self, pixel: u32, plan: &[u32], invert: bool) {
        let pixel = if invert { !pixel } else { pixel };
        let mut packed: u32 = 0;
        for &bit in plan {
            packed = (packed << 1) | ((pixel >> bit) & 1);
        }
        self.pending_bits = (self.pending_bits << plan.len()) | u64::from(packed);
        self.bit_count += plan.len() as u32;
        while self.bit_count >= 8 && !self.is_full() {
            self.bit_count -= 8;
            let byte = (self.pending_bits >> self.bit_count) as u8;
            self.out[self.byte_pos] = byte;
            self.byte_pos += 1;
        }
        self.pending_bits &= (1u64 << self.bit_count) - 1;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 && !self.is_full() {
            let byte = (self.pending_bits << (8 - self.bit_count)) as u8;
            self.out[self.byte_pos] = byte;
            self.byte_pos += 1;
        }
        self.out.truncate(self.byte_pos);
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transforms::Channel;
    use cybercipher_media::RgbaImage;

    fn ctx() -> ExecutionContext {
        ExecutionContext::new()
    }

    /// 2x2 image with distinct channel values:
    /// (0,0)=0x11223344 (0,1)=0xAABBCCDD, (1,0)=0x10203040 (1,1)=0x50607080
    fn sample() -> RgbaImage {
        RgbaImage::new(
            2,
            2,
            vec![0x1122_3344, 0xAABB_CCDD, 0x1020_3040, 0x5060_7080],
            true,
        )
        .unwrap()
    }

    #[test]
    fn defaults_extract_lsb_of_rgb_row_first() {
        // Pixels row-major: 0x44, 0xDD, 0x40, 0x80 -> LSB bits r,g,b per pixel:
        // p0: r(0x33&1=1), g(0x22&1=0), b(0x44&1=0) -> wait: ARGB word
        // 0x11223344: r=0x22, g=0x33, b=0x44 -> r=0,g=1,b=0.
        // p1 0xAABBCCDD: r=0xBB(1), g=0xCC(0), b=0xDD(1)
        // p2 0x10203040: r=0x20(0), g=0x30(0), b=0x40(0)
        // p3 0x50607080: r=0x60(0), g=0x70(0), b=0x80(0)
        // Bits MSB-first packed: 0,1,0  1,0,1  0,0,0  0,0,0
        // -> byte 0b01010100 = 0x54, rest zero-padded.
        let result = extract_bounded(
            &sample(),
            Roi::whole(2, 2),
            ExtractionOptions::default(),
            16,
            &ctx(),
        )
        .unwrap();
        assert_eq!(result.data, vec![0x54, 0x00]);
        assert_eq!(result.total_bytes, 2);
        assert!(!result.truncated);
    }

    #[test]
    fn rgb_order_selects_channel_visit_order() {
        // Only blue bit 0 selected: order does not matter for a single
        // channel; values 0x44,0xDD,0x40,0x80 -> bits 0,1,0,0 -> 0b0100_0000.
        let opts = ExtractionOptions::none().with_plane(Channel::Blue, 0, true);
        let result = extract_bounded(&sample(), Roi::whole(2, 2), opts, 16, &ctx()).unwrap();
        assert_eq!(result.data, vec![0b0100_0000]);
    }

    #[test]
    fn alpha_is_visited_first_when_selected() {
        // Alpha + red bit 0, order RGB: per pixel alpha bit then red bit.
        // alphas: 0x11(1), 0xAA(0), 0x10(0), 0x50(0); reds: 0x22(0), 0xBB(1),
        // 0x20(0), 0x60(0) -> bits 1,0 0,1 0,0 0,0 -> 0b1001_0000.
        let opts = ExtractionOptions::none()
            .with_plane(Channel::Alpha, 0, true)
            .with_plane(Channel::Red, 0, true);
        let result = extract_bounded(&sample(), Roi::whole(2, 2), opts, 16, &ctx()).unwrap();
        assert_eq!(result.data, vec![0b1001_0000]);
    }

    #[test]
    fn lsb_first_visits_planes_0_to_7() {
        // Alpha planes 0 and 7. Alpha bytes: p0 0x11 (bit0=1, bit7=0),
        // p1 0xAA (0,1), p2 0x10 (0,0), p3 0x50 (0,0). With lsb_first the
        // planes are visited 0 then 7 -> 1,0 0,1 0,0 0,0 -> 0b1001_0000.
        let opts = ExtractionOptions::none()
            .with_plane(Channel::Alpha, 0, true)
            .with_plane(Channel::Alpha, 7, true)
            .with_lsb_first(true);
        let result = extract_bounded(&sample(), Roi::whole(2, 2), opts, 16, &ctx()).unwrap();
        assert_eq!(result.data, vec![0b1001_0000]);

        // MSB-first visits plane 7 then plane 0 -> 0,1 1,0 0,0 0,0
        // -> 0b0110_0000. The two orderings genuinely differ here.
        let opts = opts.with_lsb_first(false);
        let result = extract_bounded(&sample(), Roi::whole(2, 2), opts, 16, &ctx()).unwrap();
        assert_eq!(result.data, vec![0b0110_0000]);
    }

    #[test]
    fn invert_bits_complements_pixels() {
        // Blue bit 0 inverted: ~0x44 LSB=1, ~0xDD=0, ~0x40=1, ~0x80=1
        // -> 0b1011_0000.
        let opts = ExtractionOptions::none()
            .with_plane(Channel::Blue, 0, true)
            .with_invert_bits(true);
        let result = extract_bounded(&sample(), Roi::whole(2, 2), opts, 16, &ctx()).unwrap();
        assert_eq!(result.data, vec![0b1011_0000]);
    }

    #[test]
    fn column_first_changes_bit_order() {
        // Blue bit 0, column-first: p(0,0)=0x44(0), p(0,1)=0x40(0),
        // p(1,0)=0xDD(1), p(1,1)=0x80(0) -> 0b0010_0000.
        let opts = ExtractionOptions::none()
            .with_plane(Channel::Blue, 0, true)
            .with_row_first(false);
        let result = extract_bounded(&sample(), Roi::whole(2, 2), opts, 16, &ctx()).unwrap();
        assert_eq!(result.data, vec![0b0010_0000]);
    }

    #[test]
    fn partial_trailing_byte_is_zero_padded() {
        // 5 bits total (red bit 0 of 4 pixels + 1 padding bit boundary): 4
        // selected planes of 1 pixel would give 4 bits; use 1 pixel ROI.
        let opts = ExtractionOptions::default();
        let result = extract_bounded(&sample(), Roi::new(0, 0, 1, 1), opts, 16, &ctx()).unwrap();
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0], 0b010_00000);
        assert_eq!(result.total_bytes, 1);
        assert!(!result.truncated);
    }

    #[test]
    fn bounded_extraction_reports_truncation() {
        let opts = ExtractionOptions::all_planes();
        let result = extract_bounded(&sample(), Roi::whole(2, 2), opts, 3, &ctx()).unwrap();
        // 4 pixels * 32 planes = 128 bits = 16 bytes total.
        assert_eq!(result.total_bytes, 16);
        assert_eq!(result.data.len(), 3);
        assert!(result.truncated);
    }

    #[test]
    fn roi_is_clamped_and_empty_produces_empty() {
        let opts = ExtractionOptions::default();
        let result = extract_bounded(&sample(), Roi::new(1, 1, 9, 9), opts, 16, &ctx()).unwrap();
        assert_eq!(result.data.len(), 1); // one pixel
        let empty = extract_bounded(&sample(), Roi::new(9, 9, 4, 4), opts, 16, &ctx()).unwrap();
        assert!(empty.data.is_empty());
        assert_eq!(empty.total_bytes, 0);
        assert!(!empty.truncated);
    }

    #[test]
    fn empty_selection_is_empty_with_correct_total() {
        let result = extract_bounded(
            &sample(),
            Roi::whole(2, 2),
            ExtractionOptions::none(),
            16,
            &ctx(),
        )
        .unwrap();
        assert!(result.data.is_empty());
        assert!(!result.truncated);
    }

    #[test]
    fn describe_and_masks_match_legacy_layout() {
        let opts = ExtractionOptions::none()
            .with_plane(Channel::Alpha, 7, true)
            .with_plane(Channel::Red, 0, true)
            .with_plane(Channel::Green, 0, true)
            .with_plane(Channel::Blue, 0, true);
        assert_eq!(opts.describe(), "a7 r0 g0 b0");
        assert_eq!(opts.argb_mask(), 0x8001_0101);
        assert_eq!(opts.selected_count(), 4);
    }

    #[test]
    fn legacy_order_codes_roundtrip() {
        for code in 1..=6 {
            assert_eq!(
                RgbOrder::from_legacy_code(code).unwrap().legacy_code(),
                code
            );
        }
        assert!(RgbOrder::from_legacy_code(0).is_err());
        assert!(RgbOrder::from_legacy_code(7).is_err());
    }

    #[test]
    fn argb_mask_full_alpha_renders_red_quirk_is_transform_side() {
        // The full-alpha mask reaches bit 31; the extraction side must select
        // exactly the alpha planes when asked.
        let opts = ExtractionOptions::none().with_channel(Channel::Alpha, true);
        assert_eq!(opts.argb_mask(), 0xFF000000);
    }
}
