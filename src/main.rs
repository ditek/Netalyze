use clap::Parser;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::net::{AddrParseError, Ipv4Addr};
use std::process::Command;
use std::{io, io::Write};
use std::io::BufRead;
use chrono::Local;
use std::time::Duration;

/// Run network latency and throughput tests
#[derive(Parser)]
struct Cli {
    /// IP address to ping
    #[arg(long, value_parser=validate_ip)]
    ping_ip: Option<Ipv4Addr>,
    /// IP address for iperf3 server
    #[arg(long, value_parser=validate_ip)]
    iperf_ip: Option<Ipv4Addr>,
    /// Serial port for AT commands
    #[arg(long="serial")]
    serial_port: Option<String>,
    /// Save results to a file. If not specified, print to stdout
    #[arg(short, long="save")]
    save_to_file: bool,
}

#[derive(Debug, Serialize)]
struct TestResults {
    results: Vec<TestResult>,
}
#[derive(Debug, Serialize)]
struct TestResult {
    #[serde(flatten)]
    info: TestInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency: Option<Latency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf: Option<IperfResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<CPSI>,
}

#[derive(Debug, Clone, Serialize, Default)]
struct TestInfo{
    id: u32,
    timestamp: String,
}

// Flatten the structs so we can serialize them to CSV
#[derive(Serialize, Default)]
struct TestResultRow(TestInfo, Latency, IperfResult, CpsiRow);
#[derive(Serialize, Default)]
struct CpsiRow{
    nwk_mode: String,
    rssi: String,
    rsrp: String,
}

#[derive(Debug, Default, Clone, Serialize)]
struct Latency {
    min: f64,
    avg: f64,
    max: f64,
}

#[derive(Debug, Default, Clone, Serialize)]
struct IperfResult {
    server: String,
    uplink: f64,
    downlink: f64,
    duration: i64,
}

#[derive(Debug, Clone, Serialize)]
struct CPSI {
    mode: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    lte: Option<Lte>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    nr5g_nsa: Option<Nr5gNsa>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    nr5g_sa: Option<Nr5gSa>,
}

#[derive(Debug, Clone, Serialize)]
struct Lte {
    operation_mode: String,
    mcc_mnc: String,
    tac: String,
    scell_id: String,
    pcell_id: String,
    freq_band: String,
    earfcn: String,
    dlbw: String,
    ulbw: String,
    rsrq: String,
    rsrp: String,
    rssi: String,
    rssnr: String,
}

#[derive(Debug, Clone, Serialize)]
struct Nr5gNsa {
    pcell_id: String,
    freq_band: String,
    earfcn_ssb: String,
    rsrp: String,
    rsrq: String,
    snr: String,
}

#[derive(Debug, Clone, Serialize)]
struct Nr5gSa {
    operation_mode: String,
    mcc_mnc: String,
    tac: String,
    scell_id: String,
    pcell_id: String,
    freq_band: String,
    earfcn: String,
    rsrp: String,
    rsrq: String,
    snr: String,
}

impl CPSI {
    fn to_cpsi_row(&self) -> CpsiRow {
        let mut rsrp = String::new();
        let mut rsrq = String::new();
        match self.mode.as_str() {
            "LTE" => {
                rsrp = self.lte.as_ref().unwrap().rsrp.clone();
                rsrq = self.lte.as_ref().unwrap().rsrq.clone();
            }
            "NR5G_NSA" => {
                rsrp = self.nr5g_nsa.as_ref().unwrap().rsrp.clone();
                rsrq = self.nr5g_nsa.as_ref().unwrap().rsrq.clone();
            }
            "NR5G_SA" => {
                rsrp = self.nr5g_sa.as_ref().unwrap().rsrp.clone();
                rsrq = self.nr5g_sa.as_ref().unwrap().rsrq.clone();
            }
            _ => (),
        }
        CpsiRow {
            nwk_mode: self.mode.clone(),
            rssi: rsrq,
            rsrp: rsrp,
        }
    }
}

fn validate_ip(ip: &str) -> Result<Ipv4Addr, AddrParseError> {
    ip.parse::<Ipv4Addr>()
}

fn trim_float(x: f64) -> f64 {
    format!("{:.1}", x).parse().unwrap()
}

#[allow(dead_code)]
fn run_ping(ip: Ipv4Addr) -> Result<Latency, String> {
    println!("Running ping test on {}...", ip);
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
        // println!("{output_str}");
        return Ok(latency);
    } else {
        eprintln!("Failed to parse ping output:\n{}", output_str);
        return Err("Failed to parse ping output".to_string());
    }
}

#[allow(dead_code)]
fn run_iperf3(ip: Ipv4Addr) -> Result<IperfResult, String> {
    println!("Running iperf3 test on {}...", ip);
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
        duration: json["start"]["test_start"]["duration"].as_i64().unwrap(),
        uplink: trim_float(ul * 1e-6),
        downlink: trim_float(dl * 1e-6),
    };
    // println!("{:?}", result);
    Ok(result)
}

fn run_cpsi(serial_port: &str) -> Result<CPSI, String> {
    let mut port = match serialport::new(serial_port, 115200)
    .timeout(Duration::from_millis(10))
    .open() {
        Ok(port) => port,
        Err(e) => return Err(format!("Failed to open serial port: {}", e)),
    };
    port.write_all(b"AT+CPSI?\r\n").expect("Failed to write to serial port");
    let mut reader = std::io::BufReader::new(port);
    let mut response = String::new();
    // The first line is an echo of the command
    reader.read_line(&mut response).expect("Failed to read from serial port");
    reader.read_line(&mut response).expect("Failed to read from serial port");
    println!("{}", response);
    match parse_cpsi(response.clone()) {
        Ok(cpsi) => Ok(cpsi),
        Err(e) => Err(format!("{e}\nResponse: {response}")),
    }
}

#[allow(dead_code)]
fn parse_cpsi(input: String) -> Result<CPSI, String> {
    let mode_pattern = Regex::new(r"\+CPSI: (\w+),.+").unwrap();
    let lte_pattern = Regex::new(
        r"\+CPSI: LTE,(\w+),([\d-]+),0x([\dA-Fa-f]+),(\d+),(\d+),([\w-]+),(\d+),(\d+),(\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+)").unwrap();
    let nr5g_nsa_pattern = Regex::new(r"\+CPSI: NR5G_NSA,(\d+),([\w-]+),(\d+),(-?\d+),(-?\d+),(-?\d+)").unwrap();
    let nr5g_sa_pattern = Regex::new(
        r"\+CPSI: NR5G_SA,(\w+),([\d-]+),0x([\dA-Fa-f]+),(\d+),(\d+),([\w-]+),(\d+),(-?\d+),(-?\d+),(-?\d+)").unwrap();
    // let lte_example = "+CPSI: LTE,Online,460-11,0x5A1E,187214780,257,EUTRAN-BAND3,1850,5,5,-94,-850,-545,15";
    // let nr5g_nsa_example = "+CPSI: NR5G_NSA,644,NR5G_BAND78,627264,-960,-120,95";
    // let nr5g_sa_example = "+CPSI: NR5G_SA,Online,242-12,0x765D,4955280,0,NR5G_BAND78,640704,-740,-110,240";

    let mode: &str;
    match mode_pattern.captures(&input) {
        Some(caps) => {
            mode = caps.get(1).unwrap().as_str();
        }
        None => return Err("Failed to parse mode".to_string()),
    }
    let mut lte : Option<Lte> = None;
    let mut nr5g_nsa : Option<Nr5gNsa> = None;
    let mut nr5g_sa : Option<Nr5gSa> = None;
    
    match mode {
        "LTE" => {
            lte = match lte_pattern.captures(&input) {
                Some(caps) => {
                    Some(Lte {
                        operation_mode: caps.get(1).unwrap().as_str().to_string(),
                        mcc_mnc: caps.get(2).unwrap().as_str().to_string(),
                        tac: caps.get(3).unwrap().as_str().to_string(),
                        scell_id: caps.get(4).unwrap().as_str().to_string(),
                        pcell_id: caps.get(5).unwrap().as_str().to_string(),
                        freq_band: caps.get(6).unwrap().as_str().to_string(),
                        earfcn: caps.get(7).unwrap().as_str().to_string(),
                        dlbw: caps.get(8).unwrap().as_str().to_string(),
                        ulbw: caps.get(9).unwrap().as_str().to_string(),
                        rsrq: (caps.get(10).unwrap().as_str().parse::<f64>().unwrap()/10.0).to_string(),
                        rsrp: (caps.get(11).unwrap().as_str().parse::<f64>().unwrap()/10.0).to_string(),
                        rssi: (caps.get(12).unwrap().as_str().parse::<f64>().unwrap()/10.0).to_string(),
                        rssnr: caps.get(13).unwrap().as_str().to_string(),
                    })
                }
                None => return Err("Failed to parse LTE".to_string()),
            };
        },
        "NR5G_NSA" => {
            nr5g_nsa = match nr5g_nsa_pattern.captures(&input) {
                Some(caps) => {
                    Some(Nr5gNsa {
                        pcell_id: caps.get(1).unwrap().as_str().to_string(),
                        freq_band: caps.get(2).unwrap().as_str().to_string(),
                        earfcn_ssb: caps.get(3).unwrap().as_str().to_string(),
                        rsrp: (caps.get(4).unwrap().as_str().parse::<f64>().unwrap()/10.0).to_string(),
                        rsrq: (caps.get(5).unwrap().as_str().parse::<f64>().unwrap()/10.0).to_string(),
                        snr: caps.get(6).unwrap().as_str().to_string(),
                    })
                }
                None => return Err("Failed to parse NR5G_NSA".to_string()),
            };
        }
        "NR5G_SA" => {
            nr5g_sa = match nr5g_sa_pattern.captures(&input) {
                Some(caps) => {
                    Some(Nr5gSa {
                        operation_mode: caps.get(1).unwrap().as_str().to_string(),
                        mcc_mnc: caps.get(2).unwrap().as_str().to_string(),
                        tac: caps.get(3).unwrap().as_str().to_string(),
                        scell_id: caps.get(4).unwrap().as_str().to_string(),
                        pcell_id: caps.get(5).unwrap().as_str().to_string(),
                        freq_band: caps.get(6).unwrap().as_str().to_string(),
                        earfcn: caps.get(7).unwrap().as_str().to_string(),
                        rsrp: (caps.get(8).unwrap().as_str().parse::<f64>().unwrap()/10.0).to_string(),
                        rsrq: (caps.get(9).unwrap().as_str().parse::<f64>().unwrap()/10.0).to_string(),
                        snr: caps.get(10).unwrap().as_str().to_string(),
                    })
                }
                None => return Err("Failed to parse NR5G_SA".to_string()),
            };
        
        }
        _ => return Err("Invalid mode {mode}".to_string()),
    }
    return Ok(CPSI {
        mode: mode.to_string(),
        lte: lte,
        nr5g_nsa: nr5g_nsa,
        nr5g_sa: nr5g_sa,
    });
}


fn run_test(test_id: u32, args: &Cli) -> TestResult {
    let mut result = TestResult {
        info: TestInfo{
            id: test_id,
            timestamp: Local::now().format("%Y-%m-%d_%H:%M:%S").to_string(),
        },
        latency: None,
        iperf: None,
        signal: None,
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
    if let Some(port) = &args.serial_port {
        match run_cpsi(port) {
            Ok(cpsi) => result.signal = Some(cpsi),
            Err(e) => eprintln!("Failed to run CPSI test: {}", e),
        }
    }
    result
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let mut results: Vec<TestResult> = Vec::new();
    let mut test_id  = 0;
    loop {
        print!("\nPerform test {test_id}? (Press Enter to continue, 'no' to exit): ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        match input.trim() {
            "" => {
                results.push(run_test(test_id, &args));
                test_id += 1;
            }
            "no" => break,
            _ => println!("Invalid input. Try again."),
        }
    }

    let json_results = serde_json::to_string_pretty(&results)?;
    let csv_rows: Vec<TestResultRow> = results.iter().map(|r| TestResultRow(
        r.info.clone(),
        r.latency.clone().unwrap_or_default(),
        r.iperf.clone().unwrap_or_default(),
        r.signal.clone().map(|c| c.to_cpsi_row()).unwrap_or_default())).collect();
        
    if args.save_to_file {
        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let filename = format!("nettest-{timestamp}");
        std::fs::write(format!("{filename}.json"), json_results)?;
        let mut csv_wtr = csv::Writer::from_path(format!("{filename}.csv"))?;
        csv_wtr.serialize(csv_rows)?;
        csv_wtr.flush()?;
        println!("Results saved to results.json");
    } else {
        println!("{}", json_results);
        let mut wtr = csv::Writer::from_writer(io::stdout());
        wtr.serialize(csv_rows)?;
        wtr.flush()?;
    }

    Ok(())
}
