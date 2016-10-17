#!/bin/bash

#
# This file is part of the CERTUNLP scripts for CSIRT tasks.
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

# Enter the query between quotes.
query=$1

# URLs
login_url="https://account.shodan.io/login"
filters_url="https://www.shodan.io/search?query=$query"

# Max pages: if you have a free account, then the maximum viewable pages are five.
# In other case, the maximum viewable pages can be manually modified.
maximum_pages=5

# Info for cookies and login. Edit username and password variables.
username="<USERNAME>"
password="<PASSWORD>"

data="username=$username&password=$password&grant_type=password&continue=https://www.shodan.io/"
user_agent='Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0'

regex_ip='(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
red='\033[0;31m'
NC='\033[0m' # No Color

cookie_path=$( mktemp /tmp/cookie-XXXXXXXXXXXX)
temporal_file=$( mktemp /tmp/XXXXXXXXXXXX.html )

# Processing html... Args: current page of search.
function process_html
{
	page=$1
	curl -s -A "$user_agent" -X GET "$filters_url&page=$page" --cookie $cookie_path --cookie-jar $cookie_path -o $temporal_file
	cat $temporal_file | awk 'match($0, class="ip")' | grep -E -o $regex_ip | uniq
}

function delete_temporal_files
{
	rm $temporal_file
	rm $cookie_path
}

# Login.
curl -s -L -A "$user_agent" -X POST $login_url --data $data --cookie $cookie_path --cookie-jar $cookie_path -o $temporal_file
# Verify if the login is success.
is_session_invalid=$( cat $temporal_file | awk 'match($0, /Invalid username or password/)')

if [ ${#is_session_invalid} -ne 0 ]; then
	delete_temporal_files
	echo -e "${red}Invalid username or password.${NC}"
	exit 1
fi

# When session is valid, get pages with results.
curl -s -A "$user_agent" -X GET "$filters_url&page=1" --cookie $cookie_path --cookie-jar $cookie_path -o $temporal_file

# When there are not results:
not_found_msg=$( cat $temporal_file | awk 'match($0, /No results found/)' )
if [ ${#not_found_msg} -ne 0 ]; then
	delete_temporal_files
	echo -e "${red}No results found.${NC}"
	exit 2
fi

# When query is not valid:
invalid_query=$( cat $temporal_file | awk 'match($0, /Invalid search query/)' )
if [ ${#invalid_query} -ne 0 ]; then
	delete_temporal_files
	echo "${red}Invalid search query.${NC}"
	exit 3
fi

max_pages=$maximum_pages
current_page=1

# Process first page.
process_html $current_page

# If "Next" button exists, then we continue
next=$( cat $temporal_file | awk 'match($0, /Next/)')

while [ ${#next} -ne 0 ] && [ $current_page -le $max_pages ]; do
	current_page=$((current_page+1))
	process_html $current_page
	next=$( cat $temporal_file | awk 'match($0, /Next/)')
done

delete_temporal_files

exit 0
