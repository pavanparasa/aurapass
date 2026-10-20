//! Procedurally rasterised application icons.
//!
//! AuraPass ships no bitmap assets: the tray glyph, the window/taskbar icon and
//! the brand mark are all drawn from analytic shapes at runtime. That keeps the
//! package small, scales cleanly to any size and needs no image decoder, which
//! matters for the memory budget.

/// A colour in the conventional 8-bit RGB order.
pub type Rgb = [u8; 3];

/// Brand purple (top of the gradient).
pub const BRAND_TOP: Rgb = [0x6d, 0x5c, 0xff];
/// Brand purple (bottom of the gradient).
pub const BRAND_BOTTOM: Rgb = [0x4f, 0x46, 0xe5];

/// Antialiasing factor: samples per axis, so `SS * SS` samples per pixel.
const SS: usize = 4;

/// Render a coverage mask (0 = outside, 255 = inside) for a shape test.
fn coverage_mask(size: usize, inside: impl Fn(f32, f32, f32) -> bool) -> Vec<u8> {
    let mut mask = vec![0u8; size * size];
    let s = size as f32;
    let total = (SS * SS) as f32;
    for y in 0..size {
        for x in 0..size {
            let mut hits = 0u32;
            for sy in 0..SS {
                for sx in 0..SS {
                    let fx = x as f32 + (sx as f32 + 0.5) / SS as f32;
                    let fy = y as f32 + (sy as f32 + 0.5) / SS as f32;
                    if inside(fx, fy, s) {
                        hits += 1;
                    }
                }
            }
            mask[y * size + x] = (hits as f32 / total * 255.0).round() as u8;
        }
    }
    mask
}

/// The classic keyhole: a round head over a tapering slot.
fn keyhole_inside(fx: f32, fy: f32, s: f32) -> bool {
    let cx = s * 0.5;
    let head_cy = s * 0.375;
    let head_r = s * 0.215;
    let dx = fx - cx;
    let dy = fy - head_cy;
    if dx * dx + dy * dy <= head_r * head_r {
        return true;
    }
    let top = head_cy + head_r * 0.45;
    let bottom = s * 0.88;
    if fy >= top && fy <= bottom {
        let t = ((fy - top) / (bottom - top)).clamp(0.0, 1.0);
        let half = head_r * (0.40 + 0.32 * t);
        return dx.abs() <= half;
    }
    false
}

/// A rounded square centred in a `s`-sized canvas.
fn rounded_square_inside(
    fx: f32,
    fy: f32,
    s: f32,
    radius: f32,
    inset: f32,
) -> bool {
    let half = s * 0.5 - inset;
    let c = s * 0.5;
    let qx = (fx - c).abs() - (half - radius);
    let qy = (fy - c).abs() - (half - radius);
    if qx <= 0.0 && qy <= 0.0 {
        return true;
    }
    if qx > 0.0 && qy <= 0.0 {
        return qx <= radius;
    }
    if qy > 0.0 && qx <= 0.0 {
        return qy <= radius;
    }
    qx * qx + qy * qy <= radius * radius
}

/// A monochrome keyhole glyph, premultiplied-free RGBA (fully transparent
/// outside the glyph).
pub fn keyhole_rgba(size: usize, rgb: Rgb) -> Vec<u8> {
    let mask = coverage_mask(size, keyhole_inside);
    let mut rgba = vec![0u8; size * size * 4];
    for (i, &a) in mask.iter().enumerate() {
        rgba[i * 4] = rgb[0];
        rgba[i * 4 + 1] = rgb[1];
        rgba[i * 4 + 2] = rgb[2];
        rgba[i * 4 + 3] = a;
    }
    rgba
}

/// The full-colour brand mark: a rounded purple tile with a white keyhole.
pub fn brand_rgba(size: usize) -> Vec<u8> {
    let tile = coverage_mask(size, |fx, fy, s| {
        rounded_square_inside(fx, fy, s, s * 0.22, s * 0.02)
    });
    let hole = coverage_mask(size, keyhole_inside);
    let mut rgba = vec![0u8; size * size * 4];
    let s = size as f32;
    for y in 0..size {
        let t = (y as f32 + 0.5) / s;
        let base = [
            lerp_u8(BRAND_TOP[0], BRAND_BOTTOM[0], t),
            lerp_u8(BRAND_TOP[1], BRAND_BOTTOM[1], t),
            lerp_u8(BRAND_TOP[2], BRAND_BOTTOM[2], t),
        ];
        for x in 0..size {
            let i = y * size + x;
            let k = hole[i] as f32 / 255.0;
            let r = lerp(base[0] as f32, 255.0, k);
            let g = lerp(base[1] as f32, 255.0, k);
            let b = lerp(base[2] as f32, 255.0, k);
            rgba[i * 4] = r.round() as u8;
            rgba[i * 4 + 1] = g.round() as u8;
            rgba[i * 4 + 2] = b.round() as u8;
            rgba[i * 4 + 3] = tile[i];
        }
    }
    rgba
}

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t.clamp(0.0, 1.0)
}

fn lerp_u8(a: u8, b: u8, t: f32) -> f32 {
    lerp(a as f32, b as f32, t)
}

/// Repack RGBA bytes into the big-endian ARGB32 layout the StatusNotifierItem
/// spec asks for.
pub fn to_argb32(rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rgba.len());
    for px in rgba.chunks_exact(4) {
        out.push(px[3]);
        out.push(px[0]);
        out.push(px[1]);
        out.push(px[2]);
    }
    out
}

/// The brand-mark window icon and taskbar icon for the given size.
///
/// Returns `None` only if the platform rejects the bitmap, which cannot happen
/// with the sizes we use.
pub fn window_icon(size: usize) -> Option<iced::window::Icon> {
    iced::window::icon::from_rgba(brand_rgba(size), size as u32, size as u32).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_have_expected_opacity() {
        let mask = coverage_mask(32, |fx, fy, s| keyhole_inside(fx, fy, s));
        assert!(mask.iter().any(|&a| a > 200), "the glyph should be opaque in the middle");
        assert!(mask.iter().any(|&a| a < 20), "corners should stay transparent");
    }

    #[test]
    fn argb_reorders_channels() {
        let rgba = vec![1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(to_argb32(&rgba), vec![4, 1, 2, 3, 8, 5, 6, 7]);
    }

    #[test]
    fn brand_mark_is_tiled_and_square() {
        let rgba = brand_rgba(48);
        assert_eq!(rgba.len(), 48 * 48 * 4);
        let alpha_at = |x: usize, y: usize| rgba[(y * 48 + x) * 4 + 3];
        assert!(alpha_at(24, 24) > 200, "centre should be part of the tile");
        assert!(alpha_at(0, 0) < 30, "corners are rounded away");
    }
}
