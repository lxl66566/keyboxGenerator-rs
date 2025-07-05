use openssl::{
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509, X509Name},
};

use crate::KeyMaterials;

pub fn generate_key_materials() -> Result<KeyMaterials, openssl::error::ErrorStack> {
    // 1. 生成 EC (P-256) 密钥
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let ec_pkey = PKey::from_ec_key(ec_key.clone())?;

    // 2. 生成自签名证书
    let mut x509_name = X509Name::builder()?;
    x509_name.append_entry_by_text("CN", "Keybox")?;
    let x509_name = x509_name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&x509_name)?;
    builder.set_issuer_name(&x509_name)?;
    builder.set_pubkey(&ec_pkey)?;

    // 设置一个随机的序列号
    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    builder.set_serial_number(serial.to_asn1_integer()?.as_ref())?;

    // 设置有效期为10年
    builder.set_not_before(openssl::asn1::Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(openssl::asn1::Asn1Time::days_from_now(3650)?.as_ref())?;

    // 使用 EC 私钥签名
    builder.sign(&ec_pkey, MessageDigest::sha256())?;
    let certificate = builder.build();

    // 3. 生成 RSA (2048) 密钥
    let rsa_key = Rsa::generate(2048)?;

    // 4. 将密钥和证书编码为 PEM 格式
    let ec_private_key_pem = ec_key.private_key_to_pem()?;
    let certificate_pem = certificate.to_pem()?;
    let rsa_private_key_pem = rsa_key.private_key_to_pem()?;

    Ok(KeyMaterials {
        ec_private_key: String::from_utf8(ec_private_key_pem)
            .expect("EC private key is not valid UTF-8"),
        certificate: String::from_utf8(certificate_pem).expect("certificate is not valid UTF-8"),
        rsa_private_key: String::from_utf8(rsa_private_key_pem)
            .expect("RSA private key is not valid UTF-8"),
    })
}
