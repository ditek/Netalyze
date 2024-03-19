import re
import serial


def parse_lte(match):
    operation_mode, mcc_mnc, tac, scell_id, pcell_id, freq_band, earfcn, dlbw, ulbw, rsrq, rsrp, rssi, rssnr = match.groups()
    print("LTE Mode:")
    print("Operation Mode:", operation_mode)
    print("MCC-MNC:", mcc_mnc)
    print("TAC:", tac)
    print("SCellID:", scell_id)
    print("PCellID:", pcell_id)
    print("Frequency Band:", freq_band)
    print("EARFCN:", earfcn)
    print("DLBW:", dlbw)
    print("ULBW:", ulbw)
    print("RSRQ:", float(rsrq)/10)
    print("RSRP:", float(rsrp)/10)
    print("RSSI:", float(rssi)/10)
    print("RSSNR:", rssnr)


def parse_5gnsa(match):
    pcell_id, freq_band, earfcn_ssb, rsrp, rsrq, snr = match.groups()
    print("NR5G_NSA Mode:")
    print("PCellID:", pcell_id)
    print("Frequency Band:", freq_band)
    print("EARFCN/SSB:", earfcn_ssb)
    print("RSRP:", float(rsrp)/10)
    print("RSRQ:", float(rsrq)/10)
    print("SNR:", snr)


def parse_5gsa(match):
    operation_mode, mcc_mnc, tac, scell_id, pcell_id, freq_band, earfcn, rsrp, rsrq, snr = match.groups()
    print("NR5G_SA Mode:")
    print("Operation Mode:", operation_mode)
    print("MCC-MNC:", mcc_mnc)
    print("TAC:", tac)
    print("SCellID:", scell_id)
    print("PCellID:", pcell_id)
    print("Frequency Band:", freq_band)
    print("EARFCN:", earfcn)
    print("RSRP:", float(rsrp)/10)
    print("RSRQ:", float(rsrq)/10)
    print("SNR:", snr)


def parse_cpsi(input_string: str):
    main_pattern = re.compile(r'\+CPSI: (\w+),.+')
    lte_pattern = re.compile(
        r'\+CPSI: LTE,(\w+),([\d-]+),0x([\dA-Fa-f]+),(\d+),(\d+),([\w-]+),(\d+),(\d+),(\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+)')
    nr5g_nsa_pattern = re.compile(r'\+CPSI: NR5G_NSA,(\d+),([\w-]+),(\d+),(-?\d+),(-?\d+),(-?\d+)')
    nr5g_sa_pattern = re.compile(
        r'\+CPSI: NR5G_SA,(\w+),([\d-]+),0x([\dA-Fa-f]+),(\d+),(\d+),([\w-]+),(\d+),(-?\d+),(-?\d+),(-?\d+)')

    # Match the patterns against the input string
    mode_match = main_pattern.match(input_string)
    lte_match = lte_pattern.match(input_string)
    nr5g_nsa_match = nr5g_nsa_pattern.match(input_string)
    nr5g_sa_match = nr5g_sa_pattern.match(input_string)

    if not mode_match:
        print("No mode match found.")
        return
    mode = mode_match.group(1)
    parse_func = {
        'LTE': (parse_lte, lte_match),
        'NR5G_NSA': (parse_5gnsa, nr5g_nsa_match),
        'NR5G_SA': (parse_5gsa, nr5g_sa_match),
    }
    if not all(parse_func[mode]):
        print(f'No {mode} match found.')
        return
    f = parse_func[mode][0]
    f(parse_func[mode][1])


def test():
    s1 = "+CPSI: LTE,Online,460-11,0x5A1E,187214780,257,EUTRAN-BAND3,1850,5,5,-94,-850,-545,15"
    s2 = "+CPSI: NR5G_NSA,644,NR5G_BAND78,627264,-960,-120,95"
    s3 = "+CPSI: NR5G_SA,Online,242-12,0x765D,4955280,0,NR5G_BAND78,640704,-740,-110,240"
    inputs = [s1, s2, s3]
    for s in inputs:
        parse_cpsi(s)
        print('\n')


def run():
    with serial.Serial('/dev/ttyUSB3', timeout=1) as ser:
        ser.write(b'AT+CPSI?\r')
        ser.readline()  # First line is what we sent
        line = ser.readline()
        print(line)
        line = line.decode('utf-8').strip()
        parse_cpsi(str(line))


if __name__ == '__main__':
    # test()
    run()
