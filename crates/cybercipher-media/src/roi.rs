//! Rectangular region of interest in image (pixel) coordinates.
//!
//! A 1:1 port of the StegSolver `Roi` (reference commit `c14bfa9`): an
//! immutable description of a rectangle, always used after clamping to the
//! bounds of the image it refers to. `clamp_to` guarantees the result is
//! inside `[0, maxWidth] x [0, maxHeight]` and is empty when the region does
//! not intersect that area at all.

/// A rectangular region of an image, in pixel coordinates. Sizes of zero
/// describe an empty region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Roi {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Roi {
    /// The empty region at the origin.
    pub const EMPTY: Roi = Roi {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    };

    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Roi {
            x,
            y,
            width,
            height,
        }
    }

    /// The whole image as a region.
    pub fn whole(image_width: u32, image_height: u32) -> Self {
        Roi::new(0, 0, image_width, image_height)
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// Exclusive right edge (`x + width`, saturating).
    pub fn max_x(&self) -> u32 {
        self.x.saturating_add(self.width)
    }

    /// Exclusive bottom edge (`y + height`, saturating).
    pub fn max_y(&self) -> u32 {
        self.y.saturating_add(self.height)
    }

    /// Pixel count of the region.
    pub fn area(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// Clamps the region to `[0, max_width] x [0, max_height]`, returning an
    /// empty region when it does not intersect that area.
    pub fn clamp_to(&self, max_width: u32, max_height: u32) -> Roi {
        if self.width == 0 || self.height == 0 || max_width == 0 || max_height == 0 {
            return Roi::EMPTY;
        }
        let x0 = self.x.min(max_width);
        let y0 = self.y.min(max_height);
        let x1 = self.max_x().min(max_width);
        let y1 = self.max_y().min(max_height);
        Roi::new(x0, y0, x1 - x0, y1 - y0)
    }

    /// Human readable form used in status text, e.g. `10,20 100x50`.
    pub fn describe(&self) -> String {
        format!("{},{} {}x{}", self.x, self.y, self.width, self.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_keeps_intersections_and_empties_disjoint() {
        let roi = Roi::new(2, 3, 10, 10).clamp_to(8, 9);
        assert_eq!(roi, Roi::new(2, 3, 6, 6));

        let roi = Roi::new(0, 0, 100, 100).clamp_to(8, 9);
        assert_eq!(roi, Roi::new(0, 0, 8, 9));

        assert_eq!(Roi::new(5, 5, 2, 2).clamp_to(4, 4), Roi::EMPTY);
        assert_eq!(Roi::new(2, 2, 2, 2).clamp_to(0, 4), Roi::EMPTY);
        assert_eq!(Roi::new(1, 1, 0, 2).clamp_to(4, 4), Roi::EMPTY);
    }

    #[test]
    fn edges_and_area() {
        let roi = Roi::new(1, 2, 3, 4);
        assert_eq!(roi.max_x(), 4);
        assert_eq!(roi.max_y(), 6);
        assert_eq!(roi.area(), 12);
        assert!(!roi.is_empty());
        assert!(Roi::EMPTY.is_empty());
        assert_eq!(Roi::new(3, 3, 2, 2).clamp_to(4, 4), Roi::new(3, 3, 1, 1));
    }
}
