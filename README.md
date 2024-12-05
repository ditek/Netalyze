# Network Perf
Runs a latency test (ping), throughput test (iperf3) and measures radio signal quality.
Supports x86 and ARM64 platforms.

## Usage
```sh
$ ./netalyze_x86 --help
Run network latency and throughput tests

Usage: netalyze [OPTIONS]

Options:
      --ping-ip <PING_IP>         IP address to ping
      --iperf-ip <IPERF_IP>       IP address for iperf3 server
      --serial <SERIAL_PORT>      Serial port for AT commands
  -s, --save                      Save results to a file. If not specified, print to stdout
  -u, --upload <TELEGRAF_SERVER>  Upload results to Influxdb server. Format: <server>:<port>
  -l, --label <LABEL>             Test label [default: ]
      --single                    Only run a single test
  -h, --help                      Print help
```

The script can run multiple tests in sequence prompting the user before starting a new test. When all tests are over, the results are printed to stdout or saved to a file.

Example result:

_Note: `sudo` is required when running the ping test as we test with a very small interval which is not allowed for non-root users._

```sh
$ sudo ./netalyze_aarch64 --ping-ip 1.1.1.1 --iperf-ip 127.0.0.1 --serial /dev/ttyUSB2

Perform test 0? (Press Enter to continue, 'no' to exit):
Running ping test on 1.1.1.1...
Ping { packet_loss: 0.0, min_latency: 15.457, avg_latency: 17.956, max_latency: 25.852 }
Running iperf3 test on 127.0.0.1...
AT+CPSI?
+CPSI: NR5G_SA,Online,242-12,0x765D,4955280,0,NR5G_BAND78,640704,-770,-110,290

Perform test 1? (Press Enter to continue, 'no' to exit): no
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
id,timestamp,packet_loss,min_latency,avg_latency,max_latency,uplink,downlink,duration,nwk_mode,rssi,rsrp
0,2024-04-15_17:48:22,0.0,15.457,17.956,25.852,5482.5,5416.6,1,NR5G_SA,-11,-77
```

## Output

### Stdio and Files
The script prints the result in JSON and CSV format to stdout by default. With the `--save` option, the result is saved to the files `netalyze_<timestamp>_<label>.json` and `netalyze_<timestamp>_<label>.csv`.

### Influxdb
It can also upload the results to an Influxdb server via a Telegraf socket using the `--upload` option. It sends the data in Line Protocol format.
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

# Fro cross-compilation
# Install Cross
cargo install cross
# Install Podman
# On Debian-based systems
sudo apt install podman
# On MacOS
brew install podman
```

### Build
```sh
# Only needed the first time
chmod +x ./build.sh

# Build for all platforms
./build.sh
```

The executables are then found in the [release directory](../release/).
