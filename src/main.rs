use clap::Parser;
use regex::Regex;
use std::net::{AddrParseError, Ipv4Addr};
use std::process::Command;

/// Run network latency and throughput tests
#[derive(Parser)]
struct Cli {
    /// IP address to ping
    #[arg(long, value_parser=validate_ip)]
    ping_ip: Option<Ipv4Addr>,
    /// IP address for iperf3 server
    #[arg(long, value_parser=validate_ip)]
    iperf_ip: Option<Ipv4Addr>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct Latency {
    min: f64,
    avg: f64,
    max: f64,
}

fn validate_ip(ip: &str) -> Result<Ipv4Addr, AddrParseError> {
    ip.parse::<Ipv4Addr>()
}

#[allow(dead_code)]
fn run_ping(ip: Ipv4Addr) -> Result<Latency, String> {
    println!("Running ping test on {}", ip);
    let interval_ms = 10.0;
    let pkt_count = 128;

    let output = Command::new("ping")
        .arg("-i")
        .arg((interval_ms * 1e-3).to_string())
        .arg("-c")
        .arg(pkt_count.to_string())
        .arg("-q")
        .arg(ip.to_string())
        .output()
        .expect("Failed to execute command");
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
        return Err("Failed to parse ping output".to_string());
    }
}

#[allow(dead_code)]
fn run_iperf3(ip: Ipv4Addr) -> Result<(), String> {
    println!("Running iperf3 test on {}", ip);
    let output = Command::new("iperf3")
        .arg("-c")
        .arg(ip.to_string())
        .arg("-t").arg("1")
        .output()
        .expect("Failed to execute command");

    let output_str = String::from_utf8_lossy(&output.stdout);
    println!("{}", output_str);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    if let Some(ip) = args.ping_ip {
        run_ping(ip)?;
    }
    if let Some(ip) = args.iperf_ip {
        run_iperf3(ip)?;
    }
    Ok(())
}
