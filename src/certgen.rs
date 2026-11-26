//! MITM 本地 CA：按域即时签叶子证书，TLS 走 boring，每主机一个 SslContext 由 SNI 切换。

use boring::pkey::{PKey, Private};
use boring::ssl::{
    select_next_proto, AlpnError, NameType, SniError, SslAcceptor, SslContext, SslMethod,
    SslOptions, SslSessionCacheMode,
};
use boring::x509::X509;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use time::OffsetDateTime;

/// 叶子证书有效期 365 天，签发满 358 天重签。
const LEAF_RENEW_AFTER: std::time::Duration = std::time::Duration::from_secs(358 * 24 * 3600);
/// 叶子上下文缓存上限（受管行含通配域）。
const LEAVES_CAP: usize = 512;

pub struct Authority {
    cert_pem: String, // CA 证书 PEM（save 落盘用）
    cert_der: Vec<u8>,
    ca_key: KeyPair,
    ca_x509: X509,
    /// 每主机 TLS 上下文缓存，值附签发时刻供到期重签。
    leaves: Mutex<HashMap<String, (SystemTime, Arc<SslContext>)>>,
    /// 测试期签发次数计数。
    #[cfg(test)]
    sign_count: std::sync::atomic::AtomicUsize,
}

fn issuer_of<'a>(
    cert_der: &'a [u8],
    key: &'a KeyPair,
) -> Result<Issuer<'a, &'a KeyPair>, rcgen::Error> {
    let der = rustls_pki_types::CertificateDer::from(cert_der);
    Issuer::from_ca_cert_der(&der, key)
}

impl Authority {
    /// 主机 TLS 上下文：首次访问签叶子并构建，缓存至 358 天重签，仅对受管域名签发。
    fn leaf_ctx(&self, host: &str) -> Result<Arc<SslContext>, String> {
        // 查表只占一小段锁，命中直接回。
        {
            let leaves = self.leaves.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((issued, ctx)) = leaves.get(host) {
                // 命中也查年龄，过期或时钟回拨按过期处理。
                if issued.elapsed().is_ok_and(|age| age < LEAF_RENEW_AFTER) {
                    return Ok(ctx.clone());
                }
            }
        }
        // 签发范围锁回受管域：SNI 由客户端自报。
        if !crate::pool::route::is_managed(host) {
            return Err(format!("拒绝为受管域名之外的 {host} 签发证书"));
        }
        // 锁外签发（CPU 活，在 SNI 回调/reactor 线程跑）。
        let ctx = Arc::new(sign_leaf(host, &self.cert_der, &self.ca_key, &self.ca_x509)?);
        #[cfg(test)]
        self.sign_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // 双检：并发同域只留最早落表的那份上下文。
        let mut leaves = self.leaves.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((issued, existing)) = leaves.get(host) {
            if issued.elapsed().is_ok_and(|age| age < LEAF_RENEW_AFTER) {
                return Ok(existing.clone());
            }
        }
        if leaves.len() >= LEAVES_CAP && !leaves.contains_key(host) {
            // 超限淘汰签发时刻最旧的一张。
            if let Some(oldest) = leaves
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(k, _)| k.clone())
            {
                leaves.remove(&oldest);
            }
        }
        leaves.insert(host.to_string(), (SystemTime::now(), ctx.clone()));
        Ok(ctx)
    }
}

/// 签叶子证书并建 TLS 上下文（不碰缓存表）。
fn sign_leaf(
    host: &str,
    cert_der: &[u8],
    ca_key: &KeyPair,
    ca_x509: &X509,
) -> Result<SslContext, String> {
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
    let issuer = issuer_of(cert_der, ca_key).map_err(|e| e.to_string())?;
    let cert = params
        .signed_by(&leaf_key, &issuer)
        .map_err(|e| e.to_string())?;
    let leaf_x509 = X509::from_der(cert.der()).map_err(|e| format!("叶子证书解析失败: {e}"))?;
    let key = PKey::private_key_from_der(&leaf_key.serialize_der())
        .map_err(|e| format!("叶子私钥解析失败: {e}"))?;
    mitm_host_ctx(&leaf_x509, ca_x509, &key)
}

/// 单主机上下文：证书链 + ALPN + 禁恢复，SNI 回调按主机切换。
fn mitm_host_ctx(leaf: &X509, ca: &X509, key: &PKey<Private>) -> Result<SslContext, String> {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| format!("TLS 基座初始化失败: {e}"))?;
    // ALPN h2/http/1.1。
    b.set_alpn_select_callback(|_, client| {
        select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(AlpnError::NOACK)
    });
    // 禁票据 + 禁缓存：schannel 恢复票据报 bad record MAC。
    b.set_session_cache_mode(SslSessionCacheMode::OFF);
    b.set_options(SslOptions::NO_TICKET);
    b.set_certificate(leaf)
        .map_err(|e| format!("证书装配失败: {e}"))?;
    b.set_private_key(key)
        .map_err(|e| format!("私钥装配失败: {e}"))?;
    b.add_extra_chain_cert(ca.clone())
        .map_err(|e| format!("证书链装配失败: {e}"))?;
    Ok(b.build().into_context())
}

/// 服务端 TLS 接受器：SNI 到来时按主机切换到缓存的上下文；无 SNI/非受管域 → fatal alert。
pub fn tls_acceptor_of(a: &Arc<Authority>) -> SslAcceptor {
    let authority = a.clone();
    let mut base =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("TLS 基座初始化不会失败");
    base.set_servername_callback(move |ssl, _alert| {
        let Some(host) = ssl.servername(NameType::HOST_NAME) else {
            return Err(SniError::ALERT_FATAL); // 无 SNI：无证书可出
        };
        // 查表统一转小写（SNI 大小写不敏感）。
        let ctx = authority
            .leaf_ctx(&host.to_lowercase())
            .map_err(|_| SniError::ALERT_FATAL)?;
        ssl.set_ssl_context(&ctx).map_err(|_| SniError::ALERT_FATAL)
    });
    base.build()
}

/// 加载/生成 CA；load 分支重申 key ACL，收紧失败即禁用 MITM。
pub fn load_or_generate(dir: &Path) -> Result<Arc<Authority>, String> {
    let cert_path = dir.join("ca.crt");
    let key_path = dir.join("ca.key");
    if let Ok(a) = load(&cert_path, &key_path) {
        let key_str = key_path.to_string_lossy().into_owned();
        // ACL 收不紧禁用 MITM；不删钥（保留已信任 CA）。
        if let Err(e) = crate::winsec::restrict_to_current_user(&key_str) {
            return Err(format!("ca.key ACL 收紧失败, 禁用 MITM(已有 CA): {e}"));
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
    // 只认 PKCS#8；解析失败按无 CA 重建。
    let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| format!("ca.key 解析失败: {e}"))?;
    let ca_x509 = X509::from_pem(cert_pem.as_bytes())
        .map_err(|_| "ca.crt 不是可解析的 PEM 证书".to_string())?;
    let cert_der = ca_x509
        .to_der()
        .map_err(|e| format!("ca.crt DER 转换失败: {e}"))?;
    let _ = issuer_of(&cert_der, &ca_key).map_err(|e| e.to_string())?;
    Ok(Arc::new(Authority {
        cert_pem,
        cert_der,
        ca_key,
        ca_x509,
        leaves: Mutex::new(HashMap::new()),
        #[cfg(test)]
        sign_count: std::sync::atomic::AtomicUsize::new(0),
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
    // pathlen 0：根证书只能签叶子，不能再签子 CA。
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let ca_x509 = X509::from_der(&cert_der).map_err(|e| format!("CA 证书解析失败: {e}"))?;
    Ok(Arc::new(Authority {
        cert_pem,
        cert_der,
        ca_key: key,
        ca_x509,
        leaves: Mutex::new(HashMap::new()),
        #[cfg(test)]
        sign_count: std::sync::atomic::AtomicUsize::new(0),
    }))
}

impl Authority {
    fn save(&self, cert_path: &Path, key_path: &Path) -> Result<(), String> {
        std::fs::write(cert_path, &self.cert_pem).map_err(|e| e.to_string())?;
        use std::io::Write as _;
        // 先建空文件收紧 ACL，再写私钥：写入窗口文件为空，中断不泄露。
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(key_path)
            .map_err(|e| e.to_string())?;
        if let Err(e) = crate::winsec::restrict_to_current_user(&key_path.to_string_lossy()) {
            // 收紧失败即删钥禁用 MITM。
            drop(f);
            let _ = std::fs::remove_file(key_path);
            return Err(format!("ca.key 权限收紧失败, 已删除该文件(禁用 MITM): {e}"));
        }
        f.write_all(self.ca_key.serialize_pem().as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// 根证书装入当前用户受信任根存储（免管理员）；直调证书存储 API，失败可拿错误码。
pub fn install_ca(dir: &str) -> Result<(), String> {
    use windows::Win32::Security::Cryptography::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertOpenStore, CERT_OPEN_STORE_FLAGS,
        CERT_QUERY_ENCODING_TYPE, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W,
        CERT_SYSTEM_STORE_CURRENT_USER, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let cert_path = std::path::Path::new(dir).join("ca.crt");
    use std::io::Read as _;
    let mut pem = Vec::new();
    std::fs::File::open(&cert_path)
        .map_err(|e| format!("打开 {} 失败: {e}", cert_path.display()))?
        .read_to_end(&mut pem)
        .map_err(|e| format!("读取 {} 失败: {e}", cert_path.display()))?;
    let der = X509::from_pem(&pem)
        .map_err(|_| "ca.crt 里没有 PEM 证书".to_string())?
        .to_der()
        .map_err(|e| format!("ca.crt DER 转换失败: {e}"))?;

    // "ROOT" 必须宽字符：SYSTEM provider 的 pvpara 收 LPCWSTR。
    let store_name = windows::core::w!("ROOT");
    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER),
            Some(store_name.0 as *const core::ffi::c_void),
        )
        .map_err(|e| format!("打开当前用户根存储失败: {e}"))?;
        let added = CertAddEncodedCertificateToStore(
            Some(store),
            CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
            der.as_ref(),
            CERT_STORE_ADD_REPLACE_EXISTING,
            None,
        );
        let _ = CertCloseStore(Some(store), 0);
        added.map_err(|e| format!("写入根存储失败: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/certgen.rs"]
mod tests;
