use clap::Parser;
use regex::Regex;
#[allow(unused_imports)]
use std::process::{Command, Stdio};

/// Run network latency and throughput tests
#[derive(Parser)]
struct Cli {
    /// Server IP
    ip: String,
    // #[arg(short='p', long="path")]
    // path: std::path::PathBuf,
}

#[derive(Debug)]
#[allow(dead_code)]
struct Latency {
    min: f64,
    avg: f64,
    max: f64,
}

fn run_ping(ip: &str) -> Result<Latency, &str> {
    println!("Running ping test on {}", ip);
    let interval_ms = 10.0;
    let pkt_count = 128;

    let output = Command::new("ping")
        .arg("-i")
        .arg((interval_ms * 1e-3).to_string())
        .arg("-c")
        .arg(pkt_count.to_string())
        .arg("-q")
        .arg(ip)
        .output()
        .expect("Failed to execute command");

    // let child = Command::new("ping")
    //     .arg("-i").arg((interval_ms/1000.0).to_string())
    //     .arg("-c").arg(pkt_count.to_string())
    //     .arg("-q")
    //     .arg(ip)
    //     .stdout(Stdio::piped())
    //     .spawn()
    //     .expect("Failed to execute command");
    // let output = child.wait_with_output().expect("Failed to wait on child");

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Use a regular expression to parse the rtt line
    let re = Regex::new(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms").unwrap();
    if let Some(caps) = re.captures(&output_str) {
        let latency = Latency {
            min: caps[1].parse().expect("Failed to parse min rtt"),
            avg: caps[2].parse().expect("Failed to parse avg rtt"),
            max: caps[3].parse().expect("Failed to parse max rtt"),
        };
        println!("{:?}", latency);
        return Ok(latency);
    } else {
        eprintln!("Failed to parse ping output:\n{}", output_str);
        return Err("Failed to parse ping output");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    // Check if the IP is valid
    let re = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
    if !re.is_match(&args.ip) {
        println!("Invalid IP address");
        return Ok(());
    }

    run_ping(&args.ip)?;
    Ok(())
}
