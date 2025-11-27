use url::Url;

fn main() {
    let _ = Url::parse("https://google.com"); // Just something to make sure the url crate is in the binary
    println!("Hello, world!");
}
