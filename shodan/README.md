Shodan Script
===

This script performs queries in Shodan's database from the command line.

### Dependencies
* curl.

### Use
* Copy `env-example` to `.env`.
  * `$ cp env-example .env`.
* Set variables in `.env` with your config.
* Run `$ ./shodan.sh "filter shodan"` to list ip address matches.
* Examples:
  * `$ ./shodan.sh "net:10.0.0.0/8 port:123"`.
  * `$ ./shodan.sh "Server: SQ-WEBCAM"`.
  * `$ ./shodan.sh "default password"`.
