use anyhow::bail;

use crate::api;

pub async fn run(host: &str, token: &str, target: &str, elf: &str) -> anyhow::Result<()> {
    let raw = std::fs::read(elf)?;

    println!("Trying to run {} on {}", elf, target);
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/targets/{}/run", host, target))
        .body(raw)
        .bearer_auth(token)
        .send()
        .await?;

    if res.status().is_success() {
        println!("Succesfully ran the elf on the target device.");
        println!("Teleprobe response");
        println!("==================");
        println!("{}", res.text().await.unwrap_or_else(|_| "empty".to_string()));
        Ok(())
    } else {
        println!("Error running the elf on the target device.status code");
        println!(
            "status code: {}: {}",
            res.status().as_u16(),
            res.status().canonical_reason().unwrap_or("unknown")
        );
        println!(
            "response body: {}",
            res.text().await.unwrap_or_else(|_| "empty".to_string())
        );
        bail!("Running failed!");
    }
}

pub async fn list_targets(host: &str, token: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/targets", host))
        .bearer_auth(token)
        .send()
        .await?;

    if res.status().is_success() {
        println!("Teleprobe server supports the following targets:");
        println!("{:20} {:14} {:6}", "name", "chip", "up");

        let text = res.text().await?;
        let targets: api::TargetList = serde_json::from_str(&text)?;
        let targets: Vec<String> = targets
            .targets
            .iter()
            .map(|target| format!("{:20} {:14} {:6}", target.name, target.chip, target.up))
            .collect();
        println!("{}", targets.join("\n"));
        Ok(())
    } else {
        println!("Error getting list of Teleprobe server targets");
        println!(
            "status code: {}: {}",
            res.status().as_u16(),
            res.status().canonical_reason().unwrap_or("unknown")
        );
        println!(
            "response body: {}",
            res.text().await.unwrap_or_else(|_| "empty".to_string())
        );
        bail!("Running failed!");
    }
}
