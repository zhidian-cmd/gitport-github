//! MITM 本地证书机构：生成/加载 CA，按域名即时签发叶子证书；仅池内域名 MITM。

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::PrivateKeyDer;
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
        // 先查缓存：签过的都已经过了下面那道校验，没必要每个连接重跑一遍域名表。
        {
            let leaves = self.leaves.lock().unwrap();
            if let Some(c) = leaves.get(host) {
                return Ok(c.clone());
            }
        }
        // 纵深防御：根证书本身是 Unconstrained、10 年有效，按 SNI 现签不受任何约束。
        // MITM 入口只校验 CONNECT 的目标域，但握手时的 SNI 是客户端自己给的——
        // 先 CONNECT github.com 再发 SNI=bank.com 就能借这张根证书签走别的域名。
        // 这里把签发范围锁回受管域名，非受管一律拒绝。
        if crate::config::pool_for(host).is_empty() {
            return Err(format!("拒绝为受管域名之外的 {host} 签发证书"));
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
        // SNI 在 TLS 里不区分大小写，而下面所有查表都是小写精确匹配——
        // 客户端发 GitHub.com 也必须能签，否则会被"非受管域名"挡掉。
        let host = client_hello.server_name()?.to_lowercase();
        self.authority.leaf(&host).ok()
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
    // 只认 PKCS#8——本程序 save() 与 rcgen 写出的都是它；无法解析即当无 CA 重建（重装根证书）。
    let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| format!("ca.key 解析失败: {e}"))?;
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
