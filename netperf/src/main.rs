use clap::Parser;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::{io, io::Write};
use std::io::BufRead;
use std::time::Duration;
use chrono::Local;
use telegraf::*;
use telegraf::protocol::Tag;

/// Run network latency and throughput tests
#[derive(Parser)]
#[command(version, arg_required_else_help(true))]
struct Cli {
    /// IP address to ping
    #[arg(long)]
    ping_ip: Option<Ipv4Addr>,
    /// IP address for iperf3 server
    #[arg(long)]
    iperf_ip: Option<Ipv4Addr>,
    /// Serial port for AT commands
    #[arg(long="serial")]
    serial_port: Option<String>,
    /// Save results to a file. If not specified, print to stdout
    #[arg(short, long="save")]
    save_to_file: bool,
    /// Upload results to Influxdb server.
    /// Format: <server>:<port>
    #[arg(short='u', long="upload")]
    telegraf_server: Option<SocketAddrV4>,
    /// Test label. It's possible to specify multiple Influxdb tags in the format:
    /// "my_label?key1=value1&key2=value2". Note that the quotes are required if extra tags are used.
    #[arg(short, long, default_value="")]
    label: String,
    /// Only run a single test
    #[arg(long="single")]
    single_test: bool,
    /// Speed test duration
    #[arg(short='t', default_value="10")]
    duration: u32,
    /// Speed test mode. Possible values: udp, tcp.
    #[arg(short, default_value="tcp", value_parser=validate_iperf_mode)]
    mode: String,
    /// n[KMGT] - Speed test data number of bytes. If specified, used in stead of duration.
    #[arg(short='n', value_parser=validate_iperf_size)]
    size: Option<String>,
}

#[derive(Debug, Serialize)]
struct Test {
    host: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ping_ip: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_ip: Option<Ipv4Addr>,
    results: Vec<TestResult>,
}

#[derive(Debug, Serialize)]
struct TestResult {
    #[serde(flatten)]
    info: TestInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    ping: Option<Ping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf: Option<IPerf>,
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
struct TestResultRow(TestInfoRow, Ping, IPerf, CpsiRow);

#[derive(Debug, Clone, Serialize, Default)]
struct TestInfoRow{
    host: String,
    label: String,
    id: u32,
    timestamp: String,
}

#[derive(Serialize, Default, Metric)]
#[measurement = "signal"]
struct CpsiRow{
    nwk_mode: String,
    rssi: f64,
    rsrp: f64,
}

#[derive(Debug, Default, Clone, Serialize, Metric)]
#[measurement = "latency"]
struct Ping {
    packet_loss: f64,
    min_latency: f64,
    avg_latency: f64,
    max_latency: f64,
}

#[derive(Debug, Default, Clone, Serialize, Metric)]
#[measurement = "speed"]
struct IPerf {
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
    rsrq: f64,
    rsrp: f64,
    rssi: f64,
    rssnr: f64,
}

#[derive(Debug, Clone, Serialize)]
struct Nr5gNsa {
    pcell_id: String,
    earfcn: String,
    rsrp: f64,
    rsrq: f64,
    snr: f64,
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
    rsrp: f64,
    rsrq: f64,
    snr: f64,
}

struct IperfArgs {
    ip: Ipv4Addr,
    duration: u32,
    mode: String,
    size: Option<String>,
}

impl CPSI {
    fn to_cpsi_row(&self) -> CpsiRow {
        let mut rsrp: f64 = 0.0;
        let mut rsrq: f64 = 0.0;
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

fn validate_iperf_mode(mode: &str) -> Result<String, String> {
    if mode == "tcp" || mode == "udp" {
        Ok(mode.to_string())
    } else {
        Err("Invalid mode. Possible values: tcp, udp".to_string())
    }
}

fn validate_iperf_size(size: &str) -> Result<String, String> {
    let re = Regex::new(r"\d+[KMG]").unwrap();
    if re.is_match(size) {
        Ok(size.to_string())
    } else {
        Err("Invalid size. Example values: 1M, 100K, 10G".to_string())
    }
}

fn trim_float(x: f64) -> f64 {
    format!("{:.1}", x).parse().unwrap()
}

#[allow(dead_code)]
fn run_ping(ip: Ipv4Addr) -> Result<Ping, String> {
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

    let re = Regex::new(r"([\d.]+)% packet loss.+\nrtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms").unwrap();
    if let Some(caps) = re.captures(&output_str) {
        let ping = Ping {
            packet_loss: caps[1].parse().expect("Failed to parse packet loss"),
            min_latency: caps[2].parse().expect("Failed to parse min rtt"),
            avg_latency: caps[3].parse().expect("Failed to parse avg rtt"),
            max_latency: caps[4].parse().expect("Failed to parse max rtt"),
        };
        println!("{:?}", ping);
        return Ok(ping);
    } else {
        println!("{}", output_str);
        return Err("failed to parse ping output. Make sure you use 'sudo'".to_string());
    }
}

#[allow(dead_code)]
fn run_iperf3(args: IperfArgs) -> Result<IPerf, String> {
    println!("Running iperf3 test on {}...", args.ip);
    let mut cmd = Command::new("iperf3");
    cmd.arg("-c")
        .arg(args.ip.to_string())
        .arg("-J");
    if let Some(mut size) = args.size.clone() {
        size = size.to_uppercase();
        cmd.arg("-n").arg(size);
    } else {
        cmd.arg("-t").arg(args.duration.to_string());
    }
    if args.mode == "udp" {
        cmd.arg("-u").arg("-b").arg("0");
    }

    fn run_and_get_json(cmd: &mut Command) -> Result<Value, String> {
        let output = cmd
        .output()
                .expect("Failed to execute command");
            let output_json = String::from_utf8_lossy(&output.stdout);
            let json: Value = serde_json::from_str(&output_json).expect("Failed to parse iperf3 output");
            if json["start"]["connected"].as_array().unwrap().len() > 0 {
                Ok(json)
            } else {
                Err("failed to connect to iperf3 server".to_string())
            }
    }

    let mut json = run_and_get_json(&mut cmd)?;
    let ul = json["end"]["sum_sent"]["bits_per_second"].as_f64().unwrap();
    cmd.arg("-R");
    json = run_and_get_json(&mut cmd)?;
    let dl = json["end"]["sum_received"]["bits_per_second"].as_f64().unwrap();

    let result = IPerf {
        duration: json["start"]["test_start"]["duration"].as_i64().unwrap(),
        uplink: trim_float(ul * 1e-6),
        downlink: trim_float(dl * 1e-6),
    };
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
    let mut lines = Vec::new();
    // The first line is an echo of the command
    reader.read_line(&mut response).expect("Failed to read from serial port");
    lines.push(response.clone());
    loop {
        response.clear();
        reader.read_line(&mut response).expect("Failed to read from serial port");
        lines.push(response.clone());
        if response.contains("OK") || response.contains("ERROR") {
            lines.pop();
            break;
        }
    }
    let all_lines = lines.join("\n");
    println!("{}", all_lines);
    match parse_cpsi(all_lines) {
        Ok(cpsi) => Ok(cpsi),
        Err(e) => Err(format!("{e}\nResponse: {response}")),
    }
}

#[allow(dead_code)]
fn parse_cpsi(input: String) -> Result<CPSI, String> {
    let lte_pattern = Regex::new(
        r"\+CPSI: LTE,(\w+),([\d-]+),0x([\dA-Fa-f]+),(\d+),(\d+),([\w-]+),(\d+),(\d+),(\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+)").unwrap();
    let nr5g_nsa_pattern = Regex::new(r"\+CPSI: NR5G,(\d+),(\d+),(-?\d+),(-?\d+),(-?[\.\d]+)").unwrap();
    let nr5g_sa_pattern = Regex::new(
        r"\+CPSI: NR5G_SA,(\w+),([\d-]+),0x([\dA-Fa-f]+),(\d+),(\d+),([\w-]+),(\d+),(-?\d+),(-?\d+),(-?\d+)").unwrap();

    // let lte_example = "+CPSI: LTE,Online,460-11,0x5A1E,187214780,257,EUTRAN-BAND3,1850,5,5,-94,-850,-545,15";
    // let nr5g_nsa_example = "+CPSI: NR5G,58,643296,-12,-86,8.5";
    // let nr5g_sa_example = "+CPSI: NR5G_SA,Online,242-12,0x765D,4955280,0,NR5G_BAND78,640704,-740,-110,240";
    
    // Those are from the AT Command Manual v1.01, but we see the ones in v1.00.01
    // let nr5g_nsa_pattern = Regex::new(r"\+CPSI: NR5G,(\d+),([\w-]+),(\d+),(-?\d+),(-?\d+),(-?\d+)").unwrap();
    // let nr5g_nsa_example = "+CPSI: NR5G_NSA,644,NR5G_BAND78,627264,-960,-120,95";

    let mode: &str;
    let lte_present = lte_pattern.is_match(&input);
    let nr5g_nsa_present = nr5g_nsa_pattern.is_match(&input);
    let nr5g_sa_present = nr5g_sa_pattern.is_match(&input);

    if lte_present && nr5g_nsa_present {
        mode = "NR5G_NSA";
    } else if lte_present {
        mode = "LTE";
    } else if nr5g_sa_present {
        mode = "NR5G_SA";
    } else {
        return Err("Failed to parse mode".to_string());
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
                        rsrq: caps.get(10).unwrap().as_str().parse::<f64>().unwrap()/10.0,
                        rsrp: caps.get(11).unwrap().as_str().parse::<f64>().unwrap()/10.0,
                        rssi: caps.get(12).unwrap().as_str().parse::<f64>().unwrap()/10.0,
                        rssnr: caps.get(13).unwrap().as_str().parse::<f64>().unwrap(),
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
                        earfcn: caps.get(2).unwrap().as_str().to_string(),
                        rsrp: caps.get(3).unwrap().as_str().parse::<f64>().unwrap()/10.0,
                        rsrq: caps.get(4).unwrap().as_str().parse::<f64>().unwrap()/10.0,
                        snr: caps.get(5).unwrap().as_str().parse::<f64>().unwrap(),
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
                        rsrp: caps.get(8).unwrap().as_str().parse::<f64>().unwrap()/10.0,
                        rsrq: caps.get(9).unwrap().as_str().parse::<f64>().unwrap()/10.0,
                        snr: caps.get(10).unwrap().as_str().parse::<f64>().unwrap(),
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
        ping: None,
        iperf: None,
        signal: None,
    };
    if let Some(ip) = args.ping_ip {
        match run_ping(ip) {
            Ok(ping) => result.ping = Some(ping),
            Err(e) => eprintln!("Failed to run ping test: {}", e),
        }
    }
    if let Some(ip) = args.iperf_ip {
        let args = IperfArgs {
            ip: ip,
            duration: args.duration,
            mode: args.mode.clone(),
            size: args.size.clone(),
        };
        match run_iperf3(args) {
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

fn get_hostname() -> String {
    let output = Command::new("hostname")
        .output()
        .expect("Failed to execute 'hostname' command");
    let output_str = String::from_utf8_lossy(&output.stdout);
    output_str.trim().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let test_label = args.label.clone();
    let host = get_hostname();
    let mut test = Test {
        host: host.clone(),
        label: test_label.clone(),
        ping_ip: args.ping_ip,
        iperf_ip: args.iperf_ip,
        results: Vec::new(),
    };
    let mut test_id  = 0;
    
    if args.single_test {
        test.results.push(run_test(0, &args));
    } else {
        loop {
            print!("\nPerform test {test_id}? (Press Enter to continue, 'no' to exit): ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            match input.trim() {
                "" => {
                    test.results.push(run_test(test_id, &args));
                    test_id += 1;
                }
                "no" => break,
                _ => println!("Invalid input. Try again."),
            }
        }
    }

    let json_results = serde_json::to_string_pretty(&test)?;
    let csv_rows: Vec<TestResultRow> = test.results.iter().map(|r| TestResultRow(
        TestInfoRow{
            host: host.clone(),
            label: test_label.clone(),
            id: r.info.id,
            timestamp: r.info.timestamp.clone(),
        },
        r.ping.clone().unwrap_or_default(),
        r.iperf.clone().unwrap_or_default(),
        r.signal.clone().map(|c| c.to_cpsi_row()).unwrap_or_default())).collect();
        
    if args.save_to_file {
        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let mut filename = format!("netperf_{timestamp}_{test_label}.");
        filename = filename.replace("_.", "."); // In case label is empty
        std::fs::write(format!("{filename}json"), json_results)?;
        let mut csv_wtr = csv::Writer::from_path(format!("{filename}csv"))?;
        for row in csv_rows {
            csv_wtr.serialize(row)?;
        }
        csv_wtr.flush()?;
        println!("Results saved to results.json");
    } else {
        println!("{}", json_results);
        let mut csv_wtr = csv::Writer::from_writer(io::stdout());
        for row in csv_rows {
            csv_wtr.serialize(row)?;
        }
        csv_wtr.flush()?;
    }

    if let Some(server) = args.telegraf_server {
        let server = format!("tcp://{server}");
        let mut client = telegraf::Client::new(&server.to_string()).unwrap();        
        for result in test.results {
            let mut tags = vec![
                Tag{name: String::from("host"), value: host.clone()},
                Tag{name: String::from("id"), value: result.info.id.to_string()},
            ];
            fn get_label_tags(label: &str) -> Vec<Tag> {
                // The label could include extra tags in the format: label?key1=value1&key2=value2
                let mut tags: Vec<Tag> = Vec::new();
                let re = regex::Regex::new(r"(\w+)\??(\w+=\w+&?)*").unwrap();
                let re_tags = regex::Regex::new(r"(\w+)=(\w+)&?").unwrap();
                // Do we have extra tags?
                if let Some(caps) = re.captures(label) {
                    let word = &caps[1];
                    tags.push(Tag{name: String::from("label"), value: word.to_string()});
                    println!("Word: {}", word);
                    for cap in re_tags.captures_iter(label) {
                        let (_, [key, value]) = cap.extract();
                        tags.push(Tag{name: key.to_string(), value: value.to_string()});
                    }
                    println!("Tags: {:?}", tags);        
                } else {
                    tags.push(Tag{name: String::from("label"), value: label.to_string()});
                }
                tags
            }
            tags.extend(get_label_tags(&test_label));
            if let Some(metric) = result.ping {
                let mut point = metric.to_point();
                point.tags.extend(tags.clone());
                client.write_point(&point).unwrap();
            }
            if let Some(metric) = result.iperf {
                let mut point = metric.to_point();
                point.tags.extend(tags.clone());
                client.write_point(&point).unwrap();
            }
            if let Some(metric) = result.signal {
                let mut point = metric.to_cpsi_row().to_point();
                point.tags.extend(tags.clone());
                client.write_point(&point).unwrap();
            }
        }
    }

    Ok(())
}
