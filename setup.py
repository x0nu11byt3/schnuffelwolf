#!/usr/bin/env python3

from distutils.core import setup

LONG_DESCRIPTION = """Sniffer [ small Sniffer only TCP/ICPM/UDP incoming package ] Sniffers are programs that can capture/sniff/detect packets of network traffic per packet and analyze additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script.In your projects. Aditional Note: By default it only captures 5 packets and by default I cathurate only TCP packets""".strip()

SHORT_DESCRIPTION = """Snuffelwolf - small Sniffer only TCP/ICPM/UDP incoming package""".strip()

DEPENDENCIES = [
    'PTable'
]

TEST_DEPENDENCIES = []

setup(
    name = 'snuffelwolf',
    version = '1.0.1',
    description = SHORT_DESCRIPTION,
    long_description = LONG_DESCRIPTION,
    author = 'x0nu11byt3',
    author_email = 'x0nu11byt3@proton.me',
    url = 'https://github.com/x0nu11byt3/snuffelwolf',
    packages = ['snuffelwolf',],
    classifiers = [
        'Topic :: Security :: Networking :: Sockets :: TCP :: ICMP :: UDP ',
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX',
        'Operating System :: Unix',
    ],
)
