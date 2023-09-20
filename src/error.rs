#[derive(Debug)]
pub enum Error {
    GenericError(String),
    InvalidNetwork(String),
    SilentPaymentError(silentpayments::Error),
    SilentPaymentSendingError(String),
    SilentPaymentInvalidLabels(Vec<String>),
    InvalidProtocol(String),
    IOError(std::io::Error),
    Bip32Error(bitcoin::util::bip32::Error),
}

impl From<silentpayments::Error> for Error {
    fn from(e: silentpayments::Error) -> Self {
        Error::SilentPaymentError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<bitcoin::util::bip32::Error> for Error {
    fn from(e: bitcoin::util::bip32::Error) -> Self {
        Error::Bip32Error(e)
    }
}
