[![GitHub release](https://img.shields.io/badge/release-v1.0.0-green)](https://github.com/x0nu11byt3/snuffelwolf)

# Snuffelwolf
[ small Sniffer only TCP/ICMP/UDP incoming package ] Sniffers are programs that can capture/sniff/detect packets of network traffic per packet and analyze additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script.

# Disclaimer
I point out that the hacking-related material found in the github account (x0nu11byt3) is for educational and demonstration purposes only. You are responsible for your own actions.

# Requirements
The project can be used with **python3.8** for to build. However, it requires **python3.5** as minimum. And  **Ptable** package. 
If you don't want to install python3.8 on your main operating system, you can install python3.8 on a virtual environment you can use **virtualenv** or **pipenv**

# installation
Don't despair if it takes longer than my algorithm is optimized. Remember you have to navigate a bit to see your local traffic
If you don't specify the number of packets, by default it only captures 5 packets, If you don't specify the protocol, by default I cathurate only TCP packets

```sh
# clone the repository
$ git clone https://github.com/x0nu11byt3/snuffelwolf.git
# access the project directory
$ cd snuffelwolf
```

Installation of dependencies according to your needs.

```sh
# If you are using virtualenv or simply want to install the package, 
# you can use either of these 2 commands, they both have the same purpose

# You can install keyboard package with pip or pip3
$ pip install PTable

# Or 
$ pip install -r requirements.txt

# Or if you are using pipfile you can install the package using the following command
$ pipenv install
```
# Usage
Remember,  you must be root or put the sudo command first to raise your permission level, ready! you can try dark-sniffer


```sh
# Change directory to src
$ cd src

$ python snuffelwolf.py --help

# or also you can use for display usage
$ sudo ./snuffelwolf.py -h

# remember to navigate a little bit somewhere specific to speed up the capture of packets
# for convenience use the custom mode to edit all the necessary arguments
$ sudo ./snuffelwolf.py -i
```

```sh
[+] :: Usage: sudo ./snuffelwolf.py [options] [args]

Options:
  -h, --help            show this help message and exit
  -c FILENAME_CSV, --csv-file=FILENAME_CSV
                        Save details into CSV file where the details of the
                        intercepted packets
  -j FILENAME_JSON, --json-file=FILENAME_JSON
                        Save details into JSON file where the details of the
                        intercepted packets
  -i, --interactive     Customize packet capture arguments
  -p PACKETS, --packets=PACKETS
                        Amount of packages to be captured
  -P PROTOCOL, --protocol=PROTOCOL
                        Select a specific trotocol [TCP/ICMP/UDP]
  -e, --empty-packet    Accept empty packages in the data field
  -d, --details-json    Display the data in detail in JSON Format
  -v, --version         Display version for more information
```

# Additional remarks
This project is just a simple sniffer with many limitations, if you really want to analyze packages with more depth I recommend you to see projects like [tcpdump](https://www.tcpdump.org/) and [wireshark](https://www.wireshark.org/). 

In fact wireshark provides an API for Python to analyze packages the project is known as [PyShark](https://kiminewt.github.io/pyshark/), investigate it you may be interested.
