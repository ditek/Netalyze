# Netalyze

Netalyze is a Rust-based tool that automates running and logging network tests. It runs latency tests with `ping`, throughput tests with `iperf3`, and radio signal-quality measurements through modem AT commands. It can print results to stdout, save JSON and CSV files, or upload measurements to InfluxDB through a Telegraf socket listener. The tool supports x86 and ARM64 platforms. Supports SIMCOM modems (and modems with compatible AT commands) for radio tests.

## What It Measures
- **Latency & Packet Loss**: Statistics from `ping`.
- **Throughput**: TCP or UDP uplink and downlink throughput via `iperf3`.
- **Radio Signal Quality**: Radio mode, band, RSRP, RSRQ, SNR, and related modem signal fields.
- **Workflow**: Repeated tests with labels, IDs, wait intervals, and optional upload targets.

## Table of Contents
- [What It Measures](#what-it-measures)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Output](#output)
- [Development](#development)
- [CI/CD](#cicd)

## Prerequisites
- An `iperf3` server running on the target machine you test throughput against.
- Root privileges (`sudo`) to run the tool, because the internal ping test uses a minimal interval which restricts usage for non-root users.
- *(Optional)* A [Telegraf](#influxdb) server with a socket listener configured, in case you want to upload the measurements to InfluxDB.

## Usage
```sh
$ ./netalyze_x86 --help
Run network latency and throughput tests

Usage: netalyze [OPTIONS]

Options:
      --ping-ip <PING_IP>         IP address to ping
      --iperf-ip <IPERF_IP>       IP address for iperf3 server
      --serial <SERIAL_PORT>      Serial port for AT commands (e.g. /dev/ttyUSB2)
  -s, --save                      Save results to a file. If not specified, print to stdout
      --start-id <START_ID>       Start ID (ID of the first test) [default: 0]
  -u, --upload <TELEGRAF_SERVER>  Upload results to Influxdb server. Format: <server>:<port>
  -l, --label <LABEL>             Test label. It is possible to specify multiple Influxdb tags in the format: "my_label?key1=value1&key2=value2". Note that the quotes are required if extra tags are used. [default: ]
      --single                    Only run a single test
  -w, --wait <WAIT_TIME>          Wait time between tests in seconds [default: 0]
      --subtest-wait <WAIT_TIME>  Wait time between subtests in seconds (e.g. between ping and iperf) [default: 0]
  -t <DURATION>                   Speed test duration [default: 10]
  -m <MODE>                       Speed test mode. Possible values: udp, tcp [default: tcp]
  -b <BITRATE>                    #[KMG] - Bitrate for iperf3 UDP test (e.g. 100M, 1G) [default: 1G]
  -n <SIZE>                       #[KMG] - Speed test data number of bytes. If specified, used in stead of duration
  -c, --continuous
          Run tests continuously with the specified wait_time
      --count <COUNT>
          Stop continuous mode after reaching this count (if 0, run forever) [default: 0]
  -h, --help                      Print help
  -V, --version                   Print version
```

The script can run multiple tests in sequence prompting the user before starting a new test. When all tests are over, the results are printed to stdout or saved to a file.

Example result:

```sh
$ sudo ./netalyze_aarch64 --ping-ip 1.1.1.1 --iperf-ip 127.0.0.1 --serial /dev/ttyUSB2

Perform test 0? (Press Enter to continue, 'no' to exit):
Running ping test on 1.1.1.1...
Ping { packet_loss: 0.0, min_latency: 15.457, avg_latency: 17.956, max_latency: 25.852 }
Running iperf3 test on 127.0.0.1...
AT+CPSI?
+CPSI: NR5G_SA,Online,242-12,0x765D,4955280,0,NR5G_BAND78,640704,-770,-110,290

Perform test 1? (Press Enter to continue, 'no' to exit): no
```

**JSON Output:**
```json
{
  "host": "rp2",
  "label": "",
  "ping_ip": "1.1.1.1",
  "iperf_ip": "127.0.0.1",
  "results": [
    {
      "id": 0,
      "timestamp": "2024-04-15_17:48:22",
      "ping": {
        "packet_loss": 0.0,
        "min_latency": 15.457,
        "avg_latency": 17.956,
        "max_latency": 25.852
      },
      "iperf": {
        "uplink": 5482.5,
        "downlink": 5416.6,
        "duration": 1
      },
      "signal": {
        "mode": "NR5G_SA",
        "operation_mode": "Online",
        "mcc_mnc": "242-12",
        "tac": "765D",
        "scell_id": "4955280",
        "pcell_id": "0",
        "freq_band": "NR5G_BAND78",
        "earfcn": "640704",
        "rsrp": "-77",
        "rsrq": "-11",
        "snr": "290"
      }
    }
  ]
}
```

**CSV Output:**
```csv
id,timestamp,packet_loss,min_latency,avg_latency,max_latency,uplink,downlink,duration,nwk_mode,rssi,rsrp
0,2024-04-15_17:48:22,0.0,15.457,17.956,25.852,5482.5,5416.6,1,NR5G_SA,-11,-77
```

## Output

### Stdio and Files
The script prints the result in JSON and CSV format to stdout by default. With the `--save` option, the result is saved to the files `netalyze_<timestamp>_<label>.json` and `netalyze_<timestamp>_<label>.csv`.

### Influxdb
It can also upload the results to an [InfluxDB](https://www.influxdata.com/) server via a [Telegraf](https://www.influxdata.com/time-series-platform/telegraf/) socket using the `--upload` option. It sends the data in Line Protocol format.
Use the following in `telegraf.conf` to setup the input plugin:

```toml
[[inputs.socket_listener]]
  service_address = "tcp://:8186"
```

## Development

### Dependencies
Building the project requires installing the following dependencies:

```sh
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# For cross-compilation
# Install Cross
cargo install cross
# Install Podman
# On Debian-based systems
sudo apt install podman
# On MacOS
brew install podman
```

### Run without building
```sh
cargo run -- --ping-ip 8.8.8.8
```

### Build
```sh
# Only needed the first time
chmod +x ./build.sh

# Build for all platforms
./build.sh

# On WSL you may get `bad interpreter: /bin/bash^M: no such file or directory`
# In that case, run:
dos2unix build.sh
```

The executables are then found in the [release directory](../release/).


## CI/CD
The project has a Github action configured to build the different executables when a new release is created. The only requirement is that the release tag needs to follow the format `netalyze-vX.X.X`, for example `netalyze-v1.2.0`. 
