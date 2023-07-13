#[tokio::main]
async fn main() -> Result<(), ()> {
    lndk::run().await
}

#[cfg(test)]
mod tests {
    pub mod test_utils;
}
