## Amun (amun-nx)

Adapted from https://github.com/zeroq/amun by Jan Goebel (zeroq).

amun-nx is a Python 3 port of Amun 0.2.3-devel (upstream master, commit 55714de, April 2019). Upstream Amun runs only on Python 2. The vulnerability modules, replies, shellcode detection and log files are unchanged; only what Python 3 needs was changed:

* automated 2to3 conversion (print, exceptions, dictionaries, imports), with tab indentation expanded in the files that mixed tabs and spaces;
* network data stays a string with one character per byte, as in Python 2: `core/amun_compat.py` decodes everything Amun receives as ISO-8859-1 and encodes everything it sends or stores the same way, `core/amun_struct.py` gives `struct` the Python 2 behaviour and `core/amun_re.py` compiles patterns with ASCII semantics;
* binary files (hexdumps, stored samples, images served by the HTTP module) are read and written byte for byte, integer divisions use `//`, and `vuln-check` uses `hashlib.sha1` (upstream called the non-existent `hashlib.sha`);
* new option `download_enabled` in `conf/amun.conf` (default 0 in amun-nx): with 0, Amun logs the download URL that detected shellcode points to in `logs/download.log` but does not fetch it (no HTTP, FTP or TFTP download, bind port or connect-back). Set 1 to restore upstream behaviour on an isolated, monitored sensor.

Tested with Python 3.11 (Debian 12). Python 3.11 is the last release that ships the `asyncore` and `asynchat` modules Amun is built on; Python 3.12 removed them; the `pyasyncore` and `pyasynchat` packages on PyPI provide them for later versions (not tested). Start with `python3 amun_server.py` from the Amun directory.

The original README follows.

### Amun

Amun was the first python-based low-interaction honeypot, following the concepts of Nepenthes but extending it with
more sophisticated emulation and easier maintenance.

## Requirements

* Pyhon >= 2.6 (no Python3 support yet)
* (optional) Python Psyco (available at http://psyco.sourceforge.net/)
* (optional) MySQLdb if submit-mysql or log-mysql is used
* (optional) psycopg2 if log-surfnet is used

## Installation

* Clone Git repository: `git clone https://github.com/zeroq/amun.git`
* Edit Amun main configuration file: `vim conf/amun.conf`
  * for example set the ip address for Amun to listen on (0.0.0.0 to listen on all)
  * enable or disbale vulnerability modules as needed
* start the Amun by issuing: `./amun_server`

## Tips and Tricks

In case you encounter problems with too many open files due to a lot of attackers hitting your honeypot at the same time, the following settings can be adjusted:

* To increase the maximum number of open files on Linux:
  * `echo "104854" > /proc/sys/fs/file-max`
  * `ulimit -Hn 104854`
  * `ulimit -n 104854`
* To increase the maximum number of open files on BSD:
  * `sysctl kern.maxfiles=104854`
  * `ulimit -Hn 104854`
  * `ulimit -n 104854`

## Logging

All logging information are stored in the "logs" subdirectory of your Amun installation. Following log files will be created:

* amun\_server.log
  * contains general information, errors, and alive messages of the amun server
* amun\_request\_handler.log
  * contains information about unknown exploits and not matched exploit stages
* analysis.log
  * contains information about manual shellcode analysis (performed via the -a option)
* download.log
  * contains information about all download modules (ftp, tftp, bindport, etc...)
* exploits.log
  * contains information about all exploits that where triggert
* shellcode_manager.log
  * contains information and errors of the shellcode manager
* submissions.log
  * contains information about unique downloads
* successfull_downloads.log
  * contains information about all downloaded malware
* unknown_downloads.log
  * contains information about unknown download methods
* vulnerabilities.log
  * contains information about certain vulnerability modules

## Parameters

Amun can be executed with `-a` parameter to analyse a given file for known shellcode instead of running the honeypot. 
