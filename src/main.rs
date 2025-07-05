use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use palc::Parser;
use rand::distr::{Alphanumeric, SampleString as _};

mod openssl_backend;
use openssl_backend::generate_key_materials;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// 定义一个结构体来存放生成的密钥和证书
struct KeyMaterials {
    ec_private_key: String,
    certificate: String,
    rsa_private_key: String,
}

#[derive(palc::Parser)]
struct Cli {
    device_id: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // --- 参数设置 ---
    let ec_private_key_path = PathBuf::from("ecPrivateKey.pem");
    let certificate_path = PathBuf::from("certificate.pem");
    let rsa_private_key_path = PathBuf::from("rsaPrivateKey.pem");
    let keybox_path = PathBuf::from("keybox.xml");

    // 生成一个随机设备 ID
    let device_id = cli
        .device_id
        .unwrap_or_else(|| Alphanumeric.sample_string(&mut rand::rng(), 12));

    // --- 文件覆盖检查 ---
    let all_paths = vec![
        &ec_private_key_path,
        &certificate_path,
        &rsa_private_key_path,
        &keybox_path,
    ];
    let overwrite_all = prompt_for_overwrite_if_any_exist(&all_paths)?;

    // --- 生成密钥和证书 ---
    let materials = generate_key_materials()?;

    // --- 写入 PEM 文件和 Keybox 文件 ---
    if overwrite_all {
        fs::write(&ec_private_key_path, &materials.ec_private_key)?;
        println!(
            "Successfully wrote EC private key to \"{}\".",
            ec_private_key_path.display()
        );
        fs::write(&certificate_path, &materials.certificate)?;
        println!(
            "Successfully wrote certificate to \"{}\".",
            certificate_path.display()
        );
        fs::write(&rsa_private_key_path, &materials.rsa_private_key)?;
        println!(
            "Successfully wrote RSA private key to \"{}\".",
            rsa_private_key_path.display()
        );

        // --- 生成 Keybox XML ---
        let keybox_content = format!(
            r#"<?xml version="1.0"?>
<AndroidAttestation>
<NumberOfKeyboxes>1</NumberOfKeyboxes>
<Keybox DeviceID="{device_id}">
<Key algorithm="ecdsa">
<PrivateKey format="pem">
{ec_key}</PrivateKey>
<CertificateChain>
<NumberOfCertificates>1</NumberOfCertificates>
<Certificate format="pem">
{cert}</Certificate>
</CertificateChain>
</Key>
<Key algorithm="rsa">
<PrivateKey format="pem">
{rsa_key}</PrivateKey>
</Key>
</Keybox>
</AndroidAttestation>"#,
            device_id = device_id,
            ec_key = materials.ec_private_key.trim(),
            cert = materials.certificate.trim(),
            rsa_key = materials.rsa_private_key.trim()
        );

        println!(
            "Generated keybox with a length of {}:",
            keybox_content.len()
        );
        println!("{keybox_content}");

        fs::write(&keybox_path, keybox_content)?;
        println!(
            "Successfully wrote the keybox to \"{}\".",
            keybox_path.display()
        );
    } else {
        println!("No files have been written.");
    }

    Ok(())
}

// 提示用户是否覆盖文件
fn choice(hint: &str) -> Result<bool> {
    print!("{hint} [Y/n]? ");
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;

    // 默认行为是覆盖 (输入 'Y', 'y', 或直接回车)
    Ok(choice.trim().to_lowercase() != "n")
}

// 检查给定路径中是否有文件存在，如果存在则提示用户是否覆盖
fn prompt_for_overwrite_if_any_exist(paths: &[&PathBuf]) -> Result<bool> {
    let existing_paths: Vec<&Path> = paths
        .iter()
        .map(|p| p.as_path())
        .filter(|p| p.exists())
        .collect();

    if existing_paths.is_empty() {
        return Ok(true); // 没有文件存在，直接允许写入
    }

    println!("The following files exists:");
    for path in existing_paths {
        println!("- {}", path.display());
    }
    choice("Overwrite?")
}
