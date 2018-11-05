extern crate chrono;
extern crate webpki;
extern crate rustls;
extern crate base64;
extern crate itertools;
extern crate untrusted;
extern crate serde_json;
extern crate num_bigint;
extern crate bit_vec;
extern crate hex;
extern crate sgx_types;

mod pib;

use std::env;

use std::prelude::v1::*;
use std::ptr;
use std::time::*;
use std::io::BufReader;

use sgx_types::*;

use serde_json::Value;
use chrono::prelude::*;
use itertools::Itertools;

use pib::*;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA1,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

pub const IAS_REPORT_CA : &[u8] = include_bytes!("../AttestationReportSigningCACert.pem");

pub const IAS_REPORT_SAMPLE : &[u8] = include_bytes!("../sample/report");
pub const IAS_REPORT_SIGNATURE : &[u8] = include_bytes!("../sample/report_signature");
pub const IAS_REPORT_SIGNING_CERTIFICATE : &[u8] = include_bytes!("../sample/report_signing_certificate");

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);

    let attn_report_raw = match args.get(1) {
        Some(v) => v.as_bytes(),
        _ => IAS_REPORT_SAMPLE
    };
    let sig_raw = match args.get(2) {
        Some(v) => v.as_bytes(),
        _ => IAS_REPORT_SIGNATURE
    };
    let sig_cert_raw = match args.get(3) {
        Some(v) => v.as_bytes(),
        _ => IAS_REPORT_SIGNING_CERTIFICATE
    };

//    let attn_report_raw = IAS_REPORT_SAMPLE;
//    let sig_raw = IAS_REPORT_SIGNATURE;
//    let sig_cert_raw = IAS_REPORT_SIGNING_CERTIFICATE;

    let attn_report: Value;
    match serde_json::from_slice(attn_report_raw) {
        Ok(v) => {
            attn_report = v;
        },
        _ => {
            println!("Deserialize attestation report fail.");
            println!("If you pass from `args`, check `{{}},\" are well escaped.");
            ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
        }
    };

    let sig: Vec<u8>;
    match base64::decode(&sig_raw) {
        Ok(v) => {
            sig = v;
        },
        _ => {
            println!("Decode signature fail.");
            ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
        }
    }

    let sig_cert_dec: Vec<u8>;
    match base64::decode_config(&sig_cert_raw, base64::MIME) {
        Ok(v) => {
            sig_cert_dec = v;
        },
        _ => {
            println!("Decode signature fail.");
            ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
        }
    }
    let sig_cert_input = untrusted::Input::from(&sig_cert_dec);
    let sig_cert: webpki::EndEntityCert;
    match webpki::EndEntityCert::from(sig_cert_input) {
        Ok(v) => {
            sig_cert = v;
        },
        _ => {
            println!("Bad DER");
            ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
        }
    }

    println!("==== Loaded Attestation Report ====");
    println!("{}", ::serde_json::to_string_pretty(&attn_report).unwrap());
    println!();
    println!("==== Loaded Report Signature ====");
    println!("{:02x}", sig.iter().format(""));
    println!();
    println!("==== Loaded Report Signing Certificate ====");
    println!("{:?}", sig_cert_dec.iter().format(""));
    println!();

    // Load Intel CA
    let mut ias_ca_stripped = IAS_REPORT_CA.to_vec();
    ias_ca_stripped.retain(|&x| x != 0x0d && x != 0x0a);
    let head_len = "-----BEGIN CERTIFICATE-----".len();
    let tail_len = "-----BEGIN CERTIFICATE-----".len();
    let full_len = ias_ca_stripped.len();
    let ias_ca_core : &[u8] = &ias_ca_stripped[head_len..full_len - tail_len];
    let ias_cert_dec = base64::decode_config(ias_ca_core, base64::MIME).unwrap();
    let ias_cert_input = untrusted::Input::from(&ias_cert_dec);

    let mut ca_reader = BufReader::new(&IAS_REPORT_CA[..]);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_pem_file(&mut ca_reader).expect("Failed to add CA");

    let trust_anchors: Vec<webpki::TrustAnchor> = root_store
        .roots
        .iter()
        .map(|cert| cert.to_trust_anchor())
        .collect();

    let mut chain:Vec<untrusted::Input> = Vec::new();
    chain.push(ias_cert_input);

    let now_func = webpki::Time::try_from(SystemTime::now());

    match sig_cert.verify_is_valid_tls_server_cert(
        SUPPORTED_SIG_ALGS,
        &webpki::TLSServerTrustAnchors(&trust_anchors),
        &chain,
        now_func.unwrap()) {
        Ok(_) => println!("Cert is good"),
        Err(e) => println!("Cert verification error {:?}", e),
    }

    // Verify the signature against the signing cert
    match sig_cert.verify_signature(
        &webpki::RSA_PKCS1_2048_8192_SHA256,
        untrusted::Input::from(&attn_report_raw),
        untrusted::Input::from(&sig)) {
        Ok(_) => println!("Signature good"),
        Err(e) => {
            println!("Signature verification error {:?}", e);
            ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
        },
    }

    // Verify attestation report
    // 1. Check timestamp is within 24H
    let attn_report: Value = serde_json::from_slice(attn_report_raw).unwrap();
    if let Value::String(time) = &attn_report["timestamp"] {
        let time_fixed = time.clone() + "+0000";
        let ts = DateTime::parse_from_str(&time_fixed, "%Y-%m-%dT%H:%M:%S%.f%z").unwrap().timestamp();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        println!("Time diff = {}", now - ts);
        // TODO: Let it fail when the timestamp too old.
    } else {
        println!("Failed to fetch timestamp from attestation report");
        ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
    }

    // 2. Verify quote status (mandatory field)
    if let Value::String(quote_status) = &attn_report["isvEnclaveQuoteStatus"] {
        println!("isvEnclaveQuoteStatus = {}", quote_status);
        match quote_status.as_ref() {
            "OK" => (),
            "GROUP_OUT_OF_DATE" | "GROUP_REVOKED" | "CONFIGURATION_NEEDED" => {
                // Verify platformInfoBlob for further info if status not OK
                if let Value::String(pib) = &attn_report["platformInfoBlob"] {
                    let got_pib = platform_info::from_str(&pib);
                    println!("{:?}", got_pib);
                } else {
                    println!("Failed to fetch platformInfoBlob from attestation report");
                    ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
                }
            }
            _ => {
                ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
            }
        }
    } else {
        println!("Failed to fetch isvEnclaveQuoteStatus from attestation report");
        ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
    }

    // 3. Verify quote body
    if let Value::String(quote_raw) = &attn_report["isvEnclaveQuoteBody"] {
        let quote = base64::decode(&quote_raw).unwrap();
        println!("Quote = {:?}", quote);
        // TODO: lack security check here
        let sgx_quote: sgx_quote_t = unsafe{ptr::read(quote.as_ptr() as *const _)};

        // Borrow of packed field is unsafe in future Rust releases
        // ATTENTION
        // DO SECURITY CHECK ON DEMAND
        // DO SECURITY CHECK ON DEMAND
        // DO SECURITY CHECK ON DEMAND
        unsafe {
            println!("sgx quote version = {}", sgx_quote.version);
            println!("sgx quote signature type = {}", sgx_quote.sign_type);
            println!("sgx quote report_data = {:02x}", sgx_quote.report_body.report_data.d.iter().format(""));
            println!("sgx quote mr_enclave = {:02x}", sgx_quote.report_body.mr_enclave.m.iter().format(""));
            println!("sgx quote mr_signer = {:02x}", sgx_quote.report_body.mr_signer.m.iter().format(""));
        }
    } else {
        println!("Failed to fetch isvEnclaveQuoteBody from attestation report");
        ::std::process::exit(sgx_status_t::SGX_ERROR_UNEXPECTED as i32);
    }

    ::std::process::exit(0);
}
