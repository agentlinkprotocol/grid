//! Ed25519 keys and fixed-size byte newtypes that always encode as CBOR `bstr`.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

macro_rules! bytes_newtype {
    ($name:ident, $n:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $n]);

        impl $name {
            pub const LEN: usize = $n;
            pub fn zero() -> Self {
                $name([0u8; $n])
            }
            pub fn as_bytes(&self) -> &[u8; $n] {
                &self.0
            }
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
            pub fn from_hex(s: &str) -> Result<Self> {
                let v = hex::decode(s).map_err(|e| Error::Encoding(e.to_string()))?;
                Self::from_slice(&v)
            }
            pub fn from_slice(v: &[u8]) -> Result<Self> {
                if v.len() != $n {
                    return Err(Error::Encoding(format!("expected {} bytes, got {}", $n, v.len())));
                }
                let mut a = [0u8; $n];
                a.copy_from_slice(v);
                Ok($name(a))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::zero()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl From<[u8; $n]> for $name {
            fn from(a: [u8; $n]) -> Self {
                $name(a)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.serialize_str(&self.to_hex())
                } else {
                    s.serialize_bytes(&self.0)
                }
            }
        }

        #[cfg(feature = "openapi")]
        impl utoipa::PartialSchema for $name {
            fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
                utoipa::openapi::ObjectBuilder::new()
                    .schema_type(utoipa::openapi::schema::Type::String)
                    .description(Some(format!("{} bytes, hex encoded", $n)))
                    .pattern(Some(format!("^[0-9a-f]{{{}}}$", $n * 2)))
                    .into()
            }
        }
        #[cfg(feature = "openapi")]
        impl utoipa::ToSchema for $name {}

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                if d.is_human_readable() {
                    let s = String::deserialize(d)?;
                    return $name::from_hex(&s).map_err(de::Error::custom);
                }
                struct V;
                impl<'de> de::Visitor<'de> for V {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        write!(f, "{} bytes", $n)
                    }
                    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> std::result::Result<$name, E> {
                        $name::from_slice(v).map_err(E::custom)
                    }
                    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> std::result::Result<$name, E> {
                        $name::from_slice(&v).map_err(E::custom)
                    }
                    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<$name, A::Error> {
                        let mut v = Vec::with_capacity($n);
                        while let Some(b) = seq.next_element::<u8>()? {
                            v.push(b);
                        }
                        $name::from_slice(&v).map_err(de::Error::custom)
                    }
                }
                d.deserialize_bytes(V)
            }
        }
    };
}

bytes_newtype!(Bytes16, 16);
bytes_newtype!(Bytes32, 32);
bytes_newtype!(Bytes64, 64);

/// Public key (32 bytes). Alias used for readability in signed objects.
pub type PublicKey = Bytes32;

/// An Ed25519 keypair. Used by agents, nodes and operators alike.
#[derive(Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keypair({})", self.public().to_hex())
    }
}

impl Keypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Keypair {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        Bytes32(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Bytes64 {
        Bytes64(self.signing.sign(msg).to_bytes())
    }
}

pub fn verify(public: &PublicKey, msg: &[u8], sig: &Bytes64) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&public.0).map_err(|_| Error::Signature("bad public key"))?;
    let sig = Signature::from_bytes(&sig.0);
    vk.verify(msg, &sig).map_err(|_| Error::Signature("verification failed"))
}
