# ike-scan
`ike-scan` is a tool used for scanning and gathering information about Internet Key Exchange (IKE) services, primarily used in VPNs. It helps identify IKE services, gather information about supported authentication methods, and check for vulnerabilities in the implementation.

### Installation

If `ike-scan` is not already installed on your Kali Linux system, you can install it using:

```bash
sudo apt-get install ike-scan
```

### Basic Usage

The basic syntax for using `ike-scan` is:

```bash
ike-scan [options] <target>
```

### Common Commands and Examples

1. **Basic IKE Scan**:
   To perform a basic scan on a target IP address:

   ```bash
   ike-scan 192.0.2.1
   ```

   **Expected Output**:
   ```
   Starting IKE-SCAN 1.9.1

   192.0.2.1: IKEv1, Aggressive, 3DES, MD5
   ```

2. **Scan Multiple Targets**:
   To scan multiple targets at once, you can provide a list of IPs:

   ```bash
   ike-scan 192.0.2.1 192.0.2.2
   ```

   **Expected Output**:
   ```
   Starting IKE-SCAN 1.9.1

   192.0.2.1: IKEv1, Aggressive, 3DES, MD5
   192.0.2.2: No IKE response
   ```

3. **Verbose Output**:
   To get more detailed output, use the `-v` option:

   ```bash
   ike-scan -v 192.0.2.1
   ```

   **Expected Output**:
   ```
   Starting IKE-SCAN 1.9.1

   Sending IKE_SA_INIT request to 192.0.2.1
   Received IKE_SA_INIT response
   192.0.2.1: IKEv1, Aggressive, 3DES, MD5
   ```

4. **Scan for Specific Port**:
   To specify a different port (default is UDP 500):

   ```bash
   ike-scan -P 4500 192.0.2.1
   ```

   **Expected Output**:
   ```
   Starting IKE-SCAN 1.9.1

   192.0.2.1: IKEv1, Aggressive, 3DES, MD5
   ```

5. **Save Output to File**:
   To save the scan results to a file:

   ```bash
   ike-scan -o output.txt 192.0.2.1
   ```

   This command will save the results to `output.txt`.

### Conclusion

`ike-scan` is a valuable tool for security professionals and network administrators to gather information about IKE services and assess potential vulnerabilities in VPN implementations. Always ensure you have permission to scan the target networks.




                                      ALTERNATIVE
`ike-scan` is a command-line tool used for discovering and fingerprinting Internet Key Exchange (IKE) hosts. It's commonly used to test VPN configurations and identify potential vulnerabilities.

### Installation

If `ike-scan` is not already installed on your Kali Linux system, you can install it using:

```bash
sudo apt-get install ike-scan
```

### Basic Usage

The basic syntax for using `ike-scan` is:

```bash
ike-scan [options] <target>
```

Here, `<target>` can be an IP address, a hostname, or a network range.

### Common Options and Examples

1.  **Basic Scan:**

    *   To perform a basic scan of a target, simply specify the target IP address:

    ```bash
    ike-scan 192.168.1.1
    ```

    *   **Expected Output:**

    ```
    192.168.1.1 Main Mode Handshake returned HDR=4c7d5a92 d05435c9 00000000 01000000 SA=1
    ```

    This output indicates that an IKE responder was found at the specified IP address.
2.  **Aggressive Mode Scan:**

    *   To use aggressive mode, which is faster but less reliable, use the `--aggressive` option:

    ```bash
    ike-scan --aggressive 192.168.1.1
    ```

    *   **Expected Output:**

    ```
    192.168.1.1 Aggressive Mode Handshake returned HDR=4c7d5a92 d05435c9 00000000 05000000 SA=1
    ```
3.  **Specifying a Range of IP Addresses:**

    *   To scan a range of IP addresses, specify the range in CIDR notation:

    ```bash
    ike-scan 192.168.1.0/24
    ```

    *   **Expected Output:**

    ```
    192.168.1.1 Main Mode Handshake returned HDR=4c7d5a92 d05435c9 00000000 01000000 SA=1
    192.168.1.2 [output if found]
    ```

    This will scan all IP addresses from 192.168.1.0 to 192.168.1.255.
4.  **Fingerprinting IKE Implementation:**

    *   To fingerprint the IKE implementation, use the `--vendor` option:

    ```bash
    ike-scan --vendor 192.168.1.1
    ```

    *   **Expected Output:**

    ```
    192.168.1.1 Main Mode Handshake returned HDR=4c7d5a92 d05435c9 00000000 01000000 SA=1
    Vendor ID: Cisco
    ```

    This output indicates that the IKE responder is likely a Cisco device.
5.  **Using a specific IKE version:**

    *   To specify IKE version, use the `--ikev1` or `--ikev2` options:

    ```bash
    ike-scan --ikev2 192.168.1.1
    ```

    *   **Expected Output:**

    ```
    192.168.1.1 IKEv2 Mode Handshake returned HDR=4c7d5a92 d05435c9 00000000 01000000 SA=1
    ```
6.  **Displaying Supported Transforms:**

    *   To display the supported transforms, use the `--trans` option:

    ```bash
    ike-scan --trans 192.168.1.1
    ```

    *   **Expected Output:**

    ```
    192.168.1.1:
    Transform: 1 DES-CBC SHA1 1024
    Transform: 2 3DES-CBC SHA1 1024
    ```

### Important Notes

*   `ike-scan` should be used responsibly and ethically. Always ensure you have permission to scan a target network.
*   The output of `ike-scan` can vary depending on the target and the options used.
*   Some firewalls or intrusion detection systems may block `ike-scan` traffic.

By combining these options, you can use `ike-scan` to gather detailed information about IKE implementations, which is valuable for security assessments and penetration testing.





                                  ALTERNATIVE
I'd be happy to help!

Ike-scan is a command-line tool in Kali Linux used for IKE (Internet Key Exchange) protocol scanning and identification. It can be used to identify VPN servers, detect IKE protocol implementations, and gather information about VPN deployments.

**Installation**

Ike-scan is typically pre-installed in Kali Linux. If it's not installed, you can install it using the following command:

```
sudo apt-get install ike-scan
```

**Basic Usage**

The basic syntax for using ike-scan is:

```
ike-scan [options] <target>
```

Where `<target>` is the IP address or hostname of the VPN server you want to scan.

**Common Options**

- `-A`: Aggressive mode, sends IKE packets in a way that's more likely to elicit a response from the VPN server.
- `-M`: Main mode, sends IKE packets in a way that's compliant with the IKE protocol specification.
- `-P`: PSK (Pre-Shared Key) cracking mode, attempts to crack the pre-shared key used by the VPN server.
- `-n`: Specify the IKE negotiation timeout in seconds.
- `-r`: Specify the IKE retry count.

**Examples**

1. **Basic Scan**:
   To scan a VPN server for IKE protocol support:

   ```
   ike-scan 192.168.1.100
   ```

   **Expected Output**:
   ```
   Ike-scan 1.9.4 http://www.nta-monitor.com/wiki/index.php/Ike-scan

  Ending IKE scan of 192.168.1.100

  No VPN servers found

  IKE packet details:

   Main mode packets received: 0
   Aggressive mode packets received: 0
   ```

2. **Aggressive Mode Scan**:
   To scan a VPN server using aggressive mode:

   ```
   ike-scan -A 192.168.1.100
   ```

   **Expected Output**:
   ```
   Ike-scan 1.9.4 http://www.nta-monitor.com/wiki/index.php/Ike-scan

  Ending IKE scan of 192.168.1.100

  VPN Server found!

  Vendor ID: CISCO-UNITY
   ```

3. **PSK Cracking**:
   To attempt to crack the pre-shared key used by the VPN server:

   ```
   ike-scan -P --pskcrack=dict.txt 192.168.1.100
   ```

   **Expected Output**:
   ```
   Ike-scan 1.9.4 http://www.nta-monitor.com/wiki/index.php/Ike-scan

  Ending IKE scan of 192.168.1.100

  PSK cracked: mysecretpassword
   ```

**Conclusion**

Ike-scan is a powerful tool for scanning and identifying VPN servers, as well as gathering information about IKE protocol implementations. By using various options, you can customize your scan to suit your needs.




                                           ALTERNATIVE
`ike-scan` is a tool included in Kali Linux that is used for discovering and fingerprinting IPsec VPN endpoints. It can also be used to perform IKE (Internet Key Exchange) Phase 1 negotiations and retrieve information about the VPN server. Here's how to use it, along with examples and expected output:

**Installation**

`ike-scan` is usually pre-installed on Kali Linux. If not, you can install it using:

```
sudo apt-get install ike-scan
```

**Basic Usage**

The basic syntax for using `ike-scan` is:

```
ike-scan [options] <target>
```

Where `<target>` is the IP address or domain name of the VPN server you want to scan.

**Common Options**

- `-M`: Aggressive mode (faster, but less reliable)
- `-A`: Perform IKE Phase 1 authentication
- `-P <file>`: Use a list of potential PSK (Pre-Shared Key) values from the specified file
- `-p <port>`: Specify the UDP port to use (default is 500)
- `-o <file>`: Save the output to a file

**Examples**

1. **Basic Scan**:
   To perform a basic scan on a VPN server:

   ```
   ike-scan 10.0.0.1
   ```

   **Expected Output**:
   ```
   Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
   10.0.0.1    Main Mode Cipher   : 3des-sha1-modp1024!
   10.0.0.1    Main Mode Authentication   : psk
   10.0.0.1    Aggressive Mode Cipher   : 3des-sha1-modp1024!
   10.0.0.1    Aggressive Mode Authentication   : psk
   1 key exchanged
   ```

   This output shows that the VPN server at `10.0.0.1` supports IKE Main Mode and Aggressive Mode, both using a pre-shared key (PSK) for authentication.

2. **Aggressive Mode Scan**:
   To perform a faster scan using Aggressive mode:

   ```
   ike-scan -M 10.0.0.1
   ```

   **Expected Output**:
   ```
   Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
   10.0.0.1    Aggressive Mode Cipher   : 3des-sha1-modp1024!
   10.0.0.1    Aggressive Mode Authentication   : psk
   1 key exchanged
   ```

   This command uses the `-M` option to perform the scan in Aggressive mode, which is faster but may be less reliable.

3. **Brute-Force Pre-Shared Key**:
   To attempt to brute-force the pre-shared key (PSK) used by the VPN server:

   ```
   ike-scan -A -P psk.txt 10.0.0.1
   ```

   **Expected Output**:
   ```
   Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
   10.0.0.1    Main Mode Cipher   : 3des-sha1-modp1024!
   10.0.0.1    Main Mode Authentication   : psk
   10.0.0.1    Aggressive Mode Cipher   : 3des-sha1-modp1024!
   10.0.0.1    Aggressive Mode Authentication   : psk
   1 key exchanged
   PSK is: mypassword
   ```

   This command uses the `-A` option to perform IKE Phase 1 authentication and the `-P` option to specify a file containing potential PSK values (`psk.txt`). If the correct PSK is found, it will be displayed in the output.

`ike-scan` is a powerful tool for discovering and fingerprinting IPsec VPN endpoints, as well as attempting to brute-force the pre-shared key. It can be a valuable asset in network reconnaissance and security assessments.



                                  ALTERNATIVE

`ike-scan` is a powerful tool included in Kali Linux that is used for discovering and fingerprinting IKE (Internet Key Exchange) hosts, which are typically IPsec VPN servers. It can help identify which hosts are running IKE and determine the specific IKE implementation they are using.

### How to Use ike-scan

The basic syntax for using `ike-scan` is:

```bash
ike-scan [options] [hosts...]
```

You can specify target hosts directly in the command line or read them from a file using the `--file` option. Targets can be specified as IP addresses, hostnames, or IP networks.

### Common Options

- `-h` or `--help`: Display usage information.
- `-f <fn>` or `--file=<fn>`: Read hostnames or addresses from a specified file.
- `-s <p>` or `--sport=<p>`: Set the UDP source port (default is 500).
- `-d <p>` or `--dport=<p>`: Set the UDP destination port (default is 500).
- `-r <n>` or `--retry=<n>`: Set the number of attempts per host (default is 3).
- `-t <n>` or `--timeout=<n>`: Set the initial timeout for each host (default is 500 ms).
- `-v` or `--verbose`: Display verbose progress messages.

### Examples and Expected Output

1. **Basic Discovery**:
   To discover IKE hosts in a specific network, you can run:

   ```bash
   ike-scan 192.168.1.0/24
   ```

   **Expected Output**:
   ```
   Starting ike-scan 1.7 with 256 hosts
   192.168.1.5 Main Mode Handshake returned SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024 LifeType=Seconds LifeDuration=28800)
   192.168.1.10 Notify message 14 (NO-PROPOSAL-CHOSEN)
   ```

2. **Using Verbose Mode**:
   To see more detailed output during the scan, use the `-v` option:

   ```bash
   ike-scan -v 192.168.1.0/24
   ```

   **Expected Output**:
   ```
   Sending IKE packets to 192.168.1.0/24...
   Received response from 192.168.1.5
   Main Mode Handshake returned SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024)
   ```

3. **Reading from a File**:
   If you have a list of IP addresses in a file, you can scan them using:

   ```bash
   ike-scan --file=targets.txt
   ```

   **Expected Output**:
   ```
   Starting ike-scan with hosts from targets.txt
   10.0.0.1 Main Mode Handshake returned SA=(Enc=AES Hash=SHA1 Auth=PSK Group=2:modp1024)
   ```

4. **Setting Custom Ports**:
   To specify a different source port, you can use:

   ```bash
   ike-scan --sport=4500 192.168.1.0/24
   ```

   **Expected Output**:
   ```
   Starting ike-scan with source port 4500
   192.168.1.5 Main Mode Handshake returned SA=(Enc=AES Hash=SHA1 Auth=PSK Group=2:modp1024)
   ```

### Conclusion

`ike-scan` is a versatile tool for discovering and fingerprinting IKE hosts, making it essential for network security assessments and penetration testing. By using various options, you can customize your scans to gather detailed information about IKE implementations and their configurations.

---
Learn more:
1. [ike-scan | Kali Linux Tools](https://www.kali.org/tools/ike-scan/)
2. [GitHub - royhills/ike-scan: The IKE Scanner](https://github.com/royhills/ike-scan)
3. [Ike-scan User Guide - royhills](https://www.royhills.co.uk/wiki/index.php/Ike-scan_User_Guide)
