use clap::Parser;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use serialport::SerialPort;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::{io, io::Write};
use std::io::BufRead;
use std::time::Duration;
use std::thread;
use chrono::{Local, DateTime};
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
    /// Serial port for AT commands (e.g. /dev/ttyUSB2)
    #[arg(long="serial")]
    serial_port: Option<String>,
    /// Save results to a file. If not specified, print to stdout
    #[arg(short, long="save")]
    save_to_file: bool,
    /// Start ID (ID of the first test)
    #[arg(long, default_value="0")]
    start_id: u32,
    /// Upload results to Influxdb server.
    /// Format: <server>:<port>
    #[arg(short='u', long="upload")]
    telegraf_server: Option<SocketAddrV4>,
    /// Test label. It's possible to specify multiple Influxdb tags in the format:
    /// "my_label?key1=value1&key2=value2". Note that the quotes are required if extra tags are used.
    #[arg(short, long, default_value="", verbatim_doc_comment)]
    label: String,
    /// Only run a single test
    #[arg(long="single")]
    single_test: bool,
    /// Wait time between tests in seconds
    #[arg(short='w', long="wait", default_value="0")]
    wait_time: u32,
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

#[derive(Debug, Clone, Serialize)]
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
    #[serde(serialize_with="serialize_timestamp")]
    timestamp: DateTime<Local>,
}

fn format_timestamp(timestamp: &DateTime<Local>) -> String {
    timestamp.format("%Y-%m-%d_%H-%M-%S").to_string()
}
fn serialize_timestamp<S>(timestamp: &DateTime<Local>, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    serializer.serialize_str(format_timestamp(timestamp).as_str())
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
    rsrq: f64,
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
    #[serde(default, skip_serializing_if = "is_zero")]
    duration: u32,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<String>,
    lost_percent: f64,
}

#[derive(Debug, Clone, Serialize)]
struct CPSI {
    mode: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    lte: Option<Lte>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    nr5g_nsa: Option<Lte>,
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
        CpsiRow { rsrq, rsrp }
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
fn run_iperf3(args: IperfArgs, wait_time: u32) -> Result<IPerf, String> {
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
        cmd.arg("-u").arg("-b").arg("1G");
    }
    let mut lost_percent: Vec<f64> = Vec::new();

    fn run_and_get_json(cmd: &mut Command) -> Result<Value, String> {
        let output = cmd
        .output()
                .expect("Failed to execute command");
            let output_json = String::from_utf8_lossy(&output.stdout);
            let json: Value = serde_json::from_str(&output_json).expect("Failed to parse iperf3 output");
            if json["start"]["connected"].as_array().unwrap().len() > 0 && !json["error"].as_str().is_some() {
                Ok(json)
            } else if json["error"].as_str().is_some() {
                Err(json["error"].to_string())
            } else {
                Err("failed to connect to iperf3 server".to_string())
            }
    }

    println!("Running uplink test... ");
    let mut json = run_and_get_json(&mut cmd)?;
    println!("Uplink test done");
    println!("iperf version: {}", json["start"]["version"].as_str().unwrap_or_default());
    let ul;
    if args.mode == "udp" {
        ul = json["end"]["sum"]["bits_per_second"].as_f64();
    } else {
        ul = json["end"]["sum_sent"]["bits_per_second"].as_f64();
    }
    if ul.is_none() {
        return Err(format!("failed to parse uplink speed:\n{}", json.to_string()).to_string());
    }
    lost_percent.push(json["end"]["sum"]["lost_percent"].as_f64().unwrap_or_default());
    if wait_time > 0 {
        println!("Waiting for {} seconds...", wait_time);
        thread::sleep(Duration::from_secs(wait_time as u64));
    }
    cmd.arg("-R");
    println!("Running downlink test... ");
    json = run_and_get_json(&mut cmd)?;
    println!("Downlink test done");
    let dl;
    if args.mode == "udp" {
        dl = json["end"]["sum"]["bits_per_second"].as_f64();
    } else {
        dl = json["end"]["sum_received"]["bits_per_second"].as_f64();
    }
    if dl.is_none() {
        return Err(format!("failed to parse downlink speed:\n{}", json.to_string()).to_string());
    }
    lost_percent.push(json["end"]["sum"]["lost_percent"].as_f64().unwrap_or_default());

    let result = IPerf {
        duration: args.duration,
        mode: args.mode.clone(),
        size: args.size.clone(),
        lost_percent: lost_percent.iter().sum::<f64>() / lost_percent.len() as f64,
        uplink: trim_float(ul.unwrap() * 1e-6),
        downlink: trim_float(dl.unwrap() * 1e-6),
    };
    println!("{:?}", result);
    Ok(result)
}

fn read_line_with_retry(reader: &mut std::io::BufReader<Box<dyn SerialPort>>, response: &mut String, max_attempts: usize) -> Result<(), String> {
    let mut attempts = 0;
    while attempts < max_attempts {
        match reader.read_line(response) {
            Ok(_) => return Ok(()),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    attempts += 1;
                    thread::sleep(Duration::from_millis(500));
                } else {
                    return Err(format!("Failed to read from serial port: {}", e));
                }
            }
        }
    }
    Err(format!("Operation timed out after {} attempts", max_attempts))
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
    loop {
        if let Err(e) = read_line_with_retry(&mut reader, &mut response, 5) {
            return Err(e);
        }
        if response.contains("OK") || response.contains("ERROR") {
            break;
        }
    }
    // Delete first line
    response = response.lines().skip(1).collect::<Vec<&str>>().join("\n");
    response = response.replace("\n\n", "\n");
    println!("{}", response);
    match parse_cpsi(response.clone()) {
        Ok(cpsi) => Ok(cpsi),
        Err(e) => Err(format!("{e}\nResponse: {}", response.clone()))
    }
}

#[allow(dead_code)]
fn parse_cpsi(input: String) -> Result<CPSI, String> {
    let lte_pattern = Regex::new(
        r"\+CPSI: LTE,(\w+),([\d-]+),0x([\dA-Fa-f]+),(\d+),(\d+),([\w-]+),(\d+),(\d+),(\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+)").unwrap();
    let nr5g_nsa_pattern = Regex::new(r"\+CPSI: NR5G(?:_NSA)?,(\d+),(\d+),(-?\d+),(-?\d+),(-?[\.\d]+)").unwrap();
    let nr5g_sa_pattern = Regex::new(
        r"\+CPSI: NR5G_SA,(\w+),([\d-]+),0x([\dA-Fa-f]+),(\d+),(\d+),([\w-]+),(\d+),(-?\d+),(-?\d+),(-?\d+)").unwrap();

    // let lte_example = "+CPSI: LTE,Online,460-11,0x5A1E,187214780,257,EUTRAN-BAND3,1850,5,5,-94,-850,-545,15";
    // let nr5g_nsa_example = "+CPSI: NR5G,58,643296,-12,-86,8.5";
    // OR (depending on firmware)
    // let nr5g_nsa_example = "+CPSI: NR5G_NSA,58,643296,-12,-86,8.5";
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
    let mut nr5g_nsa : Option<Lte> = None;
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
            // NSA specific parameters seem to be buggy, so we use LTE parameters since they are shared
            nr5g_nsa = match lte_pattern.captures(&input) {
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
            timestamp: Local::now(),
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
        if args.wait_time > 0 && args.iperf_ip.is_some() {
            println!("Waiting for {} seconds...", args.wait_time);
            thread::sleep(Duration::from_secs(args.wait_time as u64));
        }
    }
    if let Some(ip) = args.iperf_ip {
        let iperf_args = IperfArgs {
            ip: ip,
            duration: match args.size.clone() {
                Some(_size) => 0,
                None => args.duration.clone(),
            },
            mode: args.mode.clone(),
            size: args.size.clone(),
        };
        match run_iperf3(iperf_args, args.wait_time) {
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

/** 
 * The label could include extra tags in the format: "label?key1=value1&key2=value2"
 * This function parses the label and returns a vector of tags
*/
fn get_label_tags(label: &str) -> Vec<Tag> {
    let mut tags: Vec<Tag> = Vec::new();
    let re = regex::Regex::new(r"(\w+)\??(\w+=\w+&?)*").unwrap();
    let re_tags = regex::Regex::new(r"(\w+)=(\w+)&?").unwrap();
    // Do we have extra tags?
    if let Some(caps) = re.captures(label) {
        let word = &caps[1];
        tags.push(Tag{name: String::from("label"), value: word.to_string()});
        for cap in re_tags.captures_iter(label) {
            let (_, [key, value]) = cap.extract();
            tags.push(Tag{name: key.to_string(), value: value.to_string()});
        }
    } else {
        tags.push(Tag{name: String::from("label"), value: label.to_string()});
    }
    tags
}

fn get_label_string(tags: Vec<Tag>) -> String {
    let mut label = tags[0].value.clone();
    for tag in tags.iter().skip(1) {
        label.push_str(&format!("__{}_{}", tag.name, tag.value));
    }
    label
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let label_tags = get_label_tags(&args.label.clone());
    let test_label = get_label_string(label_tags.clone());
    let host = get_hostname();
    let mut test = Test {
        host: host.clone(),
        label: test_label.clone(),
        ping_ip: args.ping_ip,
        iperf_ip: args.iperf_ip,
        results: Vec::new(),
    };
    let mut test_id  = args.start_id;
    
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
            timestamp: format_timestamp(&r.info.timestamp),
        },
        r.ping.clone().unwrap_or_default(),
        r.iperf.clone().unwrap_or_default(),
        r.signal.clone().map(|c| c.to_cpsi_row()).unwrap_or_default())
    ).collect();

    if args.save_to_file && !test.results.is_empty(){
        let mut filename_parts = vec![test_label.clone()];
        if args.iperf_ip.is_some() {
            filename_parts.push(args.mode.clone());
            if let Some(size) = args.size.clone(){
                filename_parts.push(size);
            }
        }
        if args.serial_port.is_some() {
            let r = &test.results[0];
            if let Some(signal) = &r.signal {
                filename_parts.push(signal.mode.clone());
            }
        }
        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let mut filename = format!("netperf_{timestamp}_");
        filename.push_str(&filename_parts.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join("_"));
        filename.push('.');
        filename = filename.replace("_.", "."); // In case label is empty
        std::fs::write(format!("{filename}json"), json_results)?;
        let mut csv_wtr = csv::Writer::from_path(format!("{filename}csv"))?;
        for row in csv_rows {
            if csv_wtr.serialize(row).is_err() {
                println!("Failed to write to CSV file");
            }
        }
        if csv_wtr.flush().is_err() {
            println!("Failed to flush CSV file");
        }
        println!("Results saved to {filename}json");
    } else {
        println!("{}", json_results);
        let mut csv_wtr = csv::Writer::from_writer(io::stdout());
        for row in csv_rows {
            if csv_wtr.serialize(row).is_err() {
                println!("Failed to write to CSV file");
            }
        }
        if csv_wtr.flush().is_err() {
            println!("Failed to flush CSV file");
        }
    }

    if let Some(server) = args.telegraf_server {
        let server = format!("tcp://{server}");
        let mut client = telegraf::Client::new(&server.to_string()).unwrap();
        let num_tests = test.results.len();
        for result in test.results.clone() {
            let mut tags = vec![
                Tag{name: String::from("host"), value: host.clone()},
            ];
            if num_tests > 1 {
                tags.push(Tag{name: String::from("test_id"), value: result.info.id.to_string()});
            }
            tags.extend(label_tags.clone());
            let timestamp = protocol::Timestamp {value: result.info.timestamp.timestamp_nanos_opt().unwrap() as u64};
            if let Some(metric) = result.ping {
                let mut point = metric.to_point();
                point.timestamp = Some(timestamp.clone());
                point.tags.extend(tags.clone());
                client.write_point(&point).unwrap();
            }
            if let Some(metric) = result.iperf {
                let mut point = metric.to_point();
                point.timestamp = Some(timestamp.clone());
                point.tags.extend(tags.clone());
                point.tags.push(Tag{name: String::from("mode"), value: args.mode.clone()});
                if let Some(size) = args.size.clone(){
                    point.tags.push(Tag{name: String::from("size"), value: size.clone()});
                }
                client.write_point(&point).unwrap();
            }
            if let Some(metric) = result.signal {
                let mut point = metric.to_cpsi_row().to_point();
                point.timestamp = Some(timestamp.clone());
                point.tags.extend(tags.clone());
                point.tags.push(Tag{name: String::from("mode"), value: metric.mode.clone()});
                // println!("{:?}", point);
                client.write_point(&point).unwrap();
            }
        }
    }

    Ok(())
}
