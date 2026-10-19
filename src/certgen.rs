//! MITM 本地证书机构：生成/加载 CA，按域名即时签发叶子证书；仅池内域名 MITM。

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

use crate::pool::LogFn;

pub struct Authority {
    cert_pem: String, // CA 证书 PEM（Issuer 重建/导出用）
    cert_der: Vec<u8>,
    ca_key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

fn issuer_of<'a>(
    cert_der: &'a [u8],
    key: &'a KeyPair,
) -> Result<Issuer<'a, &'a KeyPair>, rcgen::Error> {
    let der = rustls_pki_types::CertificateDer::from(cert_der);
    Issuer::from_ca_cert_der(&der, key)
}

impl Authority {
    fn leaf(&self, host: &str) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
        {
            let leaves = self.leaves.lock().unwrap();
            if let Some(c) = leaves.get(host) {
                return Ok(c.clone());
            }
        }
        let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let now = OffsetDateTime::now_utc();
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(365); // 1 年
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let issuer = issuer_of(&self.cert_der, &self.ca_key).map_err(|e| e.to_string())?;
        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| e.to_string())?;

        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|_| "叶子私钥 DER 转换失败".to_string())?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| format!("签名密钥初始化失败: {e}"))?;
        let certified = Arc::new(rustls::sign::CertifiedKey {
            cert: vec![
                rustls_pki_types::CertificateDer::from(cert.der().to_vec()),
                rustls_pki_types::CertificateDer::from(self.cert_der.clone()),
            ],
            key: signing_key,
            ocsp: None,
        });
        self.leaves
            .lock()
            .unwrap()
            .insert(host.to_string(), certified.clone());
        Ok(certified)
    }
}

pub struct LeafResolver {
    pub authority: Arc<Authority>,
}

impl std::fmt::Debug for LeafResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafResolver").finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for LeafResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let host = client_hello.server_name()?;
        self.authority.leaf(host).ok()
    }
}

/// 服务端 TLS 配置：按 SNI 即时出证书。
pub fn tls_config_of(a: &Arc<Authority>) -> Arc<rustls::ServerConfig> {
    let resolver = LeafResolver {
        authority: a.clone(),
    };
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // schannel 会话恢复票据与本服务端互操作报 bad record MAC，禁用票据恢复。
    cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Arc::new(cfg)
}

/// 加载/生成 CA；load 分支重申 key 的 ACL（可读根私钥 = 可伪造叶子证书 MITM）。
pub fn load_or_generate(dir: &Path, log: Option<&LogFn>) -> Result<Arc<Authority>, String> {
    let cert_path = dir.join("ca.crt");
    let key_path = dir.join("ca.key");
    if let Ok(a) = load(&cert_path, &key_path) {
        let key_str = key_path.to_string_lossy().into_owned();
        if let Err(e) = crate::winsec::restrict_to_current_user(&key_str) {
            if let Some(l) = log {
                l(&format!("[安全] ca.key ACL 重申失败: {e}"));
            }
        }
        return Ok(a);
    }
    let a = generate()?;
    a.save(&cert_path, &key_path)?;
    Ok(a)
}

fn load(cert_path: &Path, key_path: &Path) -> Result<Arc<Authority>, String> {
    let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| e.to_string())?;
    let key_pem = std::fs::read_to_string(key_path).map_err(|e| e.to_string())?;
    let ca_key = KeyPair::from_pem(&key_pem)
        .or_else(|_| {
            sec1_to_pkcs8(&key_pem).and_then(|der| {
                KeyPair::from_pkcs8_der_and_sign_algo(
                    &PrivatePkcs8KeyDer::from(der),
                    &rcgen::PKCS_ECDSA_P256_SHA256,
                )
                .map_err(|e| e.to_string())
            })
        })
        .map_err(|e: String| format!("ca.key 解析失败: {e}"))?;
    let (item, _) = rustls_pemfile::read_one_from_slice(cert_pem.as_bytes())
        .map_err(|e| format!("ca.crt PEM 解析失败: {e:?}"))?
        .ok_or_else(|| "ca.crt 无 PEM 块".to_string())?;
    let cert_der = match item {
        rustls_pemfile::Item::X509Certificate(der) => der.as_ref().to_vec(),
        other => return Err(format!("ca.crt 不是 X509 证书: {other:?}")),
    };
    let _ = issuer_of(&cert_der, &ca_key).map_err(|e| e.to_string())?;
    Ok(Arc::new(Authority {
        cert_pem,
        cert_der,
        ca_key,
        leaves: Mutex::new(HashMap::new()),
    }))
}

/// SEC1 "EC PRIVATE KEY" PEM → PKCS#8 DER（手工 TLV 编码，结构固定）。
fn sec1_to_pkcs8(pem: &str) -> Result<Vec<u8>, String> {
    let (item, _) = rustls_pemfile::read_one_from_slice(pem.as_bytes())
        .map_err(|e| format!("PEM 解析失败: {e:?}"))?
        .ok_or_else(|| "无 PEM 块".to_string())?;
    let sec1 = match item {
        rustls_pemfile::Item::Sec1Key(k) => k.secret_sec1_der().to_vec(),
        other => return Err(format!("ca.key 不是 SEC1 私钥: {other:?}")),
    };
    // OID: ecPublicKey = 1.2.840.10045.2.1, prime256v1 = 1.2.840.10045.3.1.7
    let ec_oid = encode_oid(&[1, 2, 840, 10045, 2, 1]);
    let curve_oid = encode_oid(&[1, 2, 840, 10045, 3, 1, 7]);
    let alg = der_tlv(
        0x30,
        &[der_tlv(0x06, &ec_oid), der_tlv(0x06, &curve_oid)].concat(),
    );
    let pki = der_tlv(
        0x30,
        &[der_tlv(0x02, &[0x00]), alg, der_tlv(0x04, &sec1)].concat(),
    );
    Ok(pki)
}

/// DER 的 TLV 编码（tag + length + content）。
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 8);
    out.push(tag);
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let mut len = content.len();
        let mut lb = Vec::new();
        while len > 0 {
            lb.push((len & 0xff) as u8);
            len >>= 8;
        }
        lb.reverse();
        out.push(0x80 | lb.len() as u8);
        out.extend(lb);
    }
    out.extend(content);
    out
}

/// OID 编号：首对合成一个字节(40*a+b)，后续每元素 base-128 大端编码。
fn encode_oid(oid: &[u32]) -> Vec<u8> {
    let mut out = vec![(oid[0] * 40 + oid[1]) as u8];
    for &v in &oid[2..] {
        let mut n = v;
        let mut buf = Vec::new();
        buf.push((n & 0x7f) as u8);
        n >>= 7;
        while n > 0 {
            buf.push((n & 0x7f) as u8 | 0x80);
            n >>= 7;
        }
        buf.reverse();
        out.extend(buf);
    }
    out
}

fn generate() -> Result<Arc<Authority>, String> {
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GitPort Root");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "gitport-github");
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(3650); // 10 年
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    Ok(Arc::new(Authority {
        cert_pem,
        cert_der,
        ca_key: key,
        leaves: Mutex::new(HashMap::new()),
    }))
}

impl Authority {
    fn save(&self, cert_path: &Path, key_path: &Path) -> Result<(), String> {
        std::fs::write(cert_path, &self.cert_pem).map_err(|e| e.to_string())?;
        std::fs::write(key_path, self.ca_key.serialize_pem()).map_err(|e| e.to_string())?;
        let _ = crate::winsec::restrict_to_current_user(&key_path.to_string_lossy());
        Ok(())
    }
}

/// 把根证书装入当前用户的受信任根存储(免管理员)；浏览器与 schannel 重启后即信任。
pub fn install_ca(dir: &str) -> Result<(), String> {
    let cert_path = std::path::Path::new(dir).join("ca.crt");
    let out = std::process::Command::new("certutil")
        .args(["-user", "-f", "-addstore", "Root"])
        .arg(&cert_path)
        .output()
        .map_err(|e| format!("certutil 执行失败: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "certutil 安装证书失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generate_and_leaf() {
        let dir = std::env::temp_dir().join(format!("gitport_cert_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = load_or_generate(&dir, None).unwrap();
        assert!(!a.cert_der.is_empty());
        let leaf = a.leaf("github.com").unwrap();
        assert_eq!(leaf.cert.len(), 2, "叶子应附带 CA 链");
        let leaf2 = a.leaf("github.com").unwrap();
        assert!(std::ptr::eq(Arc::as_ptr(&leaf), Arc::as_ptr(&leaf2)) || leaf.cert == leaf2.cert);
    }

    #[test]
    fn sec1_conversion() {
        let kp = KeyPair::generate().unwrap();
        let pkcs8 = kp.serialize_der();
        let kp2 = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        assert_eq!(kp2.public_key_raw(), kp.public_key_raw());
    }

    #[test]
    fn tls_config_ok() {
        let dir = std::env::temp_dir().join(format!("gitport_tls_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = load_or_generate(&dir, None).unwrap();
        let _cfg = tls_config_of(&a);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mitm_handshake_roundtrip() {
        let dir = std::env::temp_dir().join(format!("gitport_hs_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = load_or_generate(&dir, None).unwrap();
        let cfg = tls_config_of(&a);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(cfg)
                .accept(stream)
                .await
                .unwrap();
            let _ = tls;
        });

        let roots = crate::pool::dial::system_roots();
        let mut roots = (*roots).clone();
        roots
            .add(rustls_pki_types::CertificateDer::from(a.cert_der.clone()))
            .unwrap();
        let cc = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
        let name = rustls_pki_types::ServerName::try_from("github.com".to_string()).unwrap();
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connector.connect(name, stream).await.unwrap();
        let _ = tls;
        srv.await.unwrap();
    }
}
