use clap::Parser;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
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
#[derive(Serialize)]
struct Latency {
    min: f64,
    avg: f64,
    max: f64,
}

#[derive(Debug, Serialize)]
struct IperfResult {
    server: String,
    timestamp: String,
    uplink: f64,
    downlink: f64,
    duration: i64,
}

#[derive(Debug, Serialize)]
struct TestResult {
    id: String,
    latency: Option<Latency>,
    iperf: Option<IperfResult>,
}

#[derive(Debug, Serialize)]
struct TestResults {
    results: Vec<TestResult>,
}

fn validate_ip(ip: &str) -> Result<Ipv4Addr, AddrParseError> {
    ip.parse::<Ipv4Addr>()
}

fn trim_float(x: f64) -> f64 {
    format!("{:.1}", x).parse().unwrap()
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
        println!("{output_str}");
        return Ok(latency);
    } else {
        eprintln!("Failed to parse ping output:\n{}", output_str);
        return Err("Failed to parse ping output".to_string());
    }
}

#[allow(dead_code)]
fn run_iperf3(ip: Ipv4Addr) -> Result<IperfResult, String> {
    println!("Running iperf3 test on {}", ip);
    let output = Command::new("iperf3")
        .arg("-c")
        .arg(ip.to_string())
        .arg("-t")
        .arg("1")
        .arg("-J")
        .output()
        .expect("Failed to execute command");

    let output_json = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&output_json).expect("Failed to parse iperf3 output");

    let ul = json["end"]["sum_sent"]["bits_per_second"].as_f64().unwrap();
    let dl = json["end"]["sum_received"]["bits_per_second"].as_f64().unwrap();
    let result = IperfResult {
        server: json["start"]["connecting_to"]["host"].as_str().unwrap().to_string(),
        timestamp: json["start"]["timestamp"]["time"].as_str().unwrap().to_string(),
        duration: json["start"]["test_start"]["duration"].as_i64().unwrap(),
        uplink: trim_float(ul * 1e-6),
        downlink: trim_float(dl * 1e-6),
    };
    // println!("{:?}", result);
    Ok(result)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let mut result = TestResult {
        id: "test".to_string(),
        latency: None,
        iperf: None,
    };
    if let Some(ip) = args.ping_ip {
        match run_ping(ip) {
            Ok(latency) => result.latency = Some(latency),
            Err(e) => eprintln!("Failed to run ping test: {}", e),
        }
    }
    if let Some(ip) = args.iperf_ip {
        match run_iperf3(ip) {
            Ok(iperf) => result.iperf = Some(iperf),
            Err(e) => eprintln!("Failed to run iperf3 test: {}", e),
        }
    }

    let json = serde_json::to_string(&result)?;
    println!("{}", json);
    Ok(())
}
