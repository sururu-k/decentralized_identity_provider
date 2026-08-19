use rand::prelude::*;

pub const P: u64 = 2_305_843_009_213_693_951; // 2^61 - 1

#[derive(Clone, Copy)]
pub struct Field {
    v: u64,
}

impl Field {
    pub fn add(a: &Field, b: &Field) -> Field {
        let v = (a.v + b.v) % P;
        Field { v }
    }

    pub fn sub(a: &Field, b: &Field) -> Field {
        let v = (a.v + P - b.v) % P;
        Field { v }
    }

    pub fn mul(a: &Field, b: &Field) -> Field {
        let v = ((a.v as u128 * b.v as u128) % P as u128) as u64;
        Field { v }
    }

    pub fn random() -> Field {
        let mut r = rand::rng();
        let v = r.random_range(0..P);
        Field { v }
    }

    pub fn bit_of(&self, n: u8) -> bool {
        let v = self.v >> n;
        (v % 2) != 0
    }
}

impl From<u64> for Field {
    fn from(value: u64) -> Self {
        Field { v: value % P }
    }
}

impl From<&Field> for u64 {
    fn from(value: &Field) -> u64 {
        value.v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_in_field() {
        assert_eq!(u64::from(&Field::add(&Field::from(1), &Field::from(2))), 3);
        assert_eq!(
            u64::from(&Field::add(&Field::from(P - 1), &Field::from(1))),
            0
        );
        assert_eq!(
            u64::from(&Field::add(&Field::from(P - 1), &Field::from(3))),
            2
        );
    }

    #[test]
    fn sub_in_field() {
        assert_eq!(u64::from(&Field::sub(&Field::from(3), &Field::from(1))), 2);
        assert_eq!(u64::from(&Field::sub(&Field::from(1), &Field::from(1))), 0);
        assert_eq!(
            u64::from(&Field::sub(&Field::from(1), &Field::from(2))),
            P - 1
        );
    }

    #[test]
    fn mul_in_field() {
        assert_eq!(u64::from(&Field::mul(&Field::from(2), &Field::from(0))), 0);
        assert_eq!(u64::from(&Field::mul(&Field::from(2), &Field::from(5))), 10);
        assert_eq!(
            u64::from(&Field::mul(&Field::from(2), &Field::from(P - 1))),
            P - 2
        );
    }

    #[test]
    fn bit_of() {
        assert!(!Field::from(6).bit_of(0));
        assert!(Field::from(6).bit_of(1));
        assert!(Field::from(6).bit_of(2));
        assert!(!Field::from(6).bit_of(3));
    }

    #[test]
    fn random() {
        let a = Field::random();
        let b = Field::random();
        let c = Field::random();
        assert_ne!(u64::from(&a), u64::from(&b));
        assert_ne!(u64::from(&b), u64::from(&c));
        assert_ne!(u64::from(&a), u64::from(&c));
        assert!(u64::from(&a) < P);
        assert!(u64::from(&b) < P);
        assert!(u64::from(&c) < P);
    }

    #[test]
    fn from_u64() {
        assert_eq!(u64::from(&Field::from(0)), 0);
        assert_eq!(u64::from(&Field::from(11)), 11);
        assert_eq!(u64::from(&Field::from(P - 1)), P - 1);
        assert_eq!(u64::from(&Field::from(P)), 0);
        assert_eq!(u64::from(&Field::from(P + 1)), 1);
    }
}
