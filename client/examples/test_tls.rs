use rustls::RootCertStore;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[tokio::main]
async fn main() {
    let url = "wss://relay-eu.gnoppix.org/ws";
    let request = url.into_client_request().unwrap();
    
    let mut root_store = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = root_store.add(cert);
    }
    
    println!("Loaded {} root certs", root_store.len());
    
    let verifier = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    println!("Config created successfully");
}
