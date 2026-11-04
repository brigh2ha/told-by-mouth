//! Locations in millionths of a degree and the haversine distance.

use crate::cbor::{Cbor, Dec, Enc};
use crate::error::Error;

/// A latitude/longitude in millionths of a degree (about 11 cm), 4 bytes each.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GeoPoint {
    pub lat: i32,
    pub lon: i32,
}

const EARTH_RADIUS_M: f64 = 6_371_000.0;

impl GeoPoint {
    pub fn new(lat: i32, lon: i32) -> Result<Self, Error> {
        let p = Self { lat, lon };
        p.check()?;
        Ok(p)
    }

    /// From decimal degrees, rounded to the nearest micro-degree.
    pub fn from_degrees(lat: f64, lon: f64) -> Result<Self, Error> {
        if !lat.is_finite() || !lon.is_finite() {
            return Err(Error::BadLocation);
        }
        Self::new((lat * 1e6).round() as i32, (lon * 1e6).round() as i32)
    }

    pub fn check(&self) -> Result<(), Error> {
        if (-90_000_000..=90_000_000).contains(&self.lat)
            && (-180_000_000..=180_000_000).contains(&self.lon)
        {
            Ok(())
        } else {
            Err(Error::BadLocation)
        }
    }

    /// Straight-line (great-circle) distance in metres.
    pub fn distance_m(&self, other: &GeoPoint) -> f64 {
        let rad = |micro: i32| (micro as f64 / 1e6).to_radians();
        let (lat1, lat2) = (rad(self.lat), rad(other.lat));
        let dlat = lat2 - lat1;
        let dlon = rad(other.lon) - rad(self.lon);
        let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
        2.0 * EARTH_RADIUS_M * a.sqrt().min(1.0).asin()
    }
}

/// Encoded as two items (lat, lon) inside the parent array, not a nested
/// array, to keep records flat.
impl GeoPoint {
    pub(crate) fn encode_into(&self, e: &mut Enc) {
        e.i64(self.lat as i64).i64(self.lon as i64);
    }
    pub(crate) fn decode_from(d: &mut Dec<'_>) -> Result<Self, Error> {
        let lat = d.i32()?;
        let lon = d.i32()?;
        Self::new(lat, lon).map_err(|_| Error::Decode("location out of range".into()))
    }
}

impl Cbor for GeoPoint {
    fn encode(&self, e: &mut Enc) {
        e.array(2);
        self.encode_into(e);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(2)?;
        Self::decode_from(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn haversine_matches_known_distances() {
        // Seoul City Hall to Gangnam Station is about 8.9 km.
        let city_hall = GeoPoint::from_degrees(37.566_535, 126.977_969).unwrap();
        let gangnam = GeoPoint::from_degrees(37.497_942, 127.027_621).unwrap();
        let d = city_hall.distance_m(&gangnam);
        assert!((8_700.0..9_100.0).contains(&d), "{d}");

        // 0.001 degree of latitude is about 111 m.
        let a = GeoPoint::new(37_000_000, 127_000_000).unwrap();
        let b = GeoPoint::new(37_001_000, 127_000_000).unwrap();
        assert!((a.distance_m(&b) - 111.2).abs() < 0.5);
        assert_eq!(a.distance_m(&a), 0.0);
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(GeoPoint::new(90_000_001, 0).is_err());
        assert!(GeoPoint::new(0, -180_000_001).is_err());
        assert!(GeoPoint::from_degrees(f64::NAN, 0.0).is_err());
        let p = GeoPoint::new(-33_868_820, 151_209_296).unwrap();
        assert_eq!(GeoPoint::from_cbor(&p.to_cbor()).unwrap(), p);
    }
}
