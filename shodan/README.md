Shodan Script
===

This script performs queries to Shodan's database from the command line.

### Dependencies
* curl.

### Use
* Set Shodan `username` and `password` in file script.
* Run `$ ./shodan.sh "filter shodan"` to list ip address matches.
* Examples:
  * `$ ./shodan.sh "net:10.0.0.0/8 port:123"`.
  * `$ ./shodan.sh "Server: SQ-WEBCAM"`.
  * `$ ./shodan.sh "default password"`.
