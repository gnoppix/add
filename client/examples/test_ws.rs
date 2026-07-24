use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};

#[tokio::main]
async fn main() {
    let url = "wss://relay-eu.gnoppix.org/ws";
    let request = url.into_client_request().unwrap();
    
    println!("Connecting to {}", url);
    match connect_async(request).await {
        Ok((ws, _)) => println!("Connected!"),
        Err(e) => println!("Error: {}", e),
    }
}
