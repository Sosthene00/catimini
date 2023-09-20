use core::fmt;
use silentpayments::sending::SilentPaymentAddress;
use crate::Error;

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum CatiminiAddress {
    Bip47,
    PrivatePayment,
    SilentPayment(SilentPaymentAddress),
}

impl CatiminiAddress {
    pub fn get_protocol(&self) -> &'static str {
        match self {
            Self::Bip47 => "bip47",
            Self::PrivatePayment => "private payment",
            Self::SilentPayment(_) => "silent payment"
        }
    }

    pub fn is_testnet(&self) -> bool {
        match self {
            Self::SilentPayment(a) => a.is_testnet(),
            _ => unimplemented!()
        }
    }

    pub fn test_protocol(candidate: &str) -> Result<&'static str, Error> {
        if let Ok(res) = Self::try_from(candidate) {
            return Ok(res.get_protocol());
        } else {
            return Err(Error::InvalidProtocol(format!("Unknown protocol for address {}", candidate)));
        }
    }
}

impl TryInto<SilentPaymentAddress> for CatiminiAddress {
    type Error = Error;

    fn try_into(self) -> Result<SilentPaymentAddress, Self::Error> {
        match self {
            CatiminiAddress::SilentPayment(silent_payment_address) => {
                Ok(silent_payment_address)
            },
            _ => Err(Error::InvalidProtocol(format!("Expected silent payment, got {}", self.get_protocol())))
        }
    }
}

impl Into<String> for CatiminiAddress {
    fn into(self) -> String {
        match self {
            CatiminiAddress::SilentPayment(silent_payment_recipient) => {
                silent_payment_recipient.into()
            },
            _ => unimplemented!()
        }
    }
}

impl TryFrom<String> for CatiminiAddress {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(sp) = SilentPaymentAddress::try_from(value.clone()) {
            return Ok(Self::SilentPayment(sp));
        } else {
            return Err(Error::GenericError("Unknown address".to_owned()));
        }
    }
}

impl TryFrom<&str> for CatiminiAddress {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Ok(sp) = SilentPaymentAddress::try_from(value.clone()) {
            return Ok(Self::SilentPayment(sp));
        } else {
            return Err(Error::GenericError("Unknown address".to_owned()));
        }
    }
}

impl fmt::Display for CatiminiAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CatiminiAddress::SilentPayment(silent_payment_recipient) => {
                write!(f, "{}", silent_payment_recipient)
            },
            _ => unimplemented!()
        }
    }
}
