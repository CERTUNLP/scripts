#!/bin/bash

#
# This file is part of the CERTUNLP scripts for CSIRT tasks.
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

source $(dirname $BASH_SOURCE)/.env

# Enter the query between quotes.
query=$1

# URLs
login_url="https://account.shodan.io/login"
filters_url="https://www.shodan.io/search?query=$query"
total_query="https://www.shodan.io/search/_summary?query=$query"

# Logging file:
logging_file="$logging_dir/shodan.log"

[ -d $logging_dir ] || mkdir -p $logging_dir

# Max pages: if you have a free account, then the maximum viewable pages are five.
# In other case, the maximum viewable pages can be manually modified.
maximum_pages=5

user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36'

regex_ip='(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
red='\033[0;31m'
NC='\033[0m' # No Color

cookie_path=$( mktemp /tmp/cookie-XXXXXXXXXXXX)
temporal_file=$( mktemp /tmp/temporalXXXXXXXXXXXX.html )
results_file=$( mktemp /tmp/results-XXXXXXXXXXXX.txt )

# Processing html... Args: current page of search.
function process_html
{
	page=$1
	curl -s -A "$user_agent" -X GET "$filters_url&page=$page" --cookie $cookie_path --cookie-jar $cookie_path -o $temporal_file
	cat $temporal_file | awk 'match($0, /class="ip"/)' | grep -E -o $regex_ip | uniq >> $results_file
}

function delete_temporal_files
{
	rm $temporal_file
	rm $cookie_path
	rm $results_file
}

# Getting CSRF token
token=$(curl -s -A "$user_agent" https://account.shodan.io/login --cookie $cookie_path --cookie-jar $cookie_path | awk -F 'value' '/csrf_token/ {print $2}' | cut -d"'" -f2 2> /dev/null )
token=$(echo $token | awk '{print $1;}')

data="username=$username&password=$password&grant_type=password&continue=https%3A%2F%2Faccount.shodan.io%2F%3Flanguage%3Des%26language%3Des&csrf_token=$token&login_submit=Log+in"

# Login.
curl -s -L -A "$user_agent" -X POST $login_url --data $data --cookie $cookie_path --cookie-jar $cookie_path -o $temporal_file
# Verify if the login is success.
is_session_invalid=$( cat $temporal_file | awk 'match($0, /Invalid username or password/)')

if [ ${#is_session_invalid} -ne 0 ]; then
	delete_temporal_files
	echo "Query: '$query', Invalid username or password." >> $logging_file
	echo -e "${red}Invalid username or password.${nc}"
	exit 1
fi

# When session is valid, get pages with results.
curl -s -A "$user_agent" -X GET "$filters_url&page=1" --cookie $cookie_path --cookie-jar $cookie_path -o $temporal_file

# When there are not results:
not_found_msg=$( cat $temporal_file | awk 'match($0, /No results found/)' )
if [ ${#not_found_msg} -ne 0 ]; then
	delete_temporal_files
	# Logging data:
	echo "Query: '$query', Extracted: 0, Total: 0" >> $logging_file
	echo -e "${red}No results found.${NC}"
	exit 2
fi

# When query is not valid:
invalid_query=$( cat $temporal_file | awk 'match($0, /Invalid search query/)' )
if [ ${#invalid_query} -ne 0 ]; then
	delete_temporal_files
	echo "Query: '$query', Invalid search query." >> $logging_file
	echo "${red}Invalid search query.${NC}"
	exit 3
fi

# When internal error in server:
internal_error=$( cat $temporal_file | awk 'match($0, /Web server is returning an unknown error/)' )
if [ ${#internal_error} -ne 0 ]; then
	delete_temporal_files
	echo "Query: '$query', Internal error server." >> $logging_file
	echo "${red}Error 520. Try again in few minutes.${NC}"
	exit 4
fi

max_pages=$maximum_pages
current_page=1

# Getting total results from Shodan:
#total_shodan=$( cat $temporal_file | awk 'match($0, /Total results: /)' | sed "s/[^0-9]//g" )
total_shodan=$(curl -s "$total_query" | grep "class=\"bignumber\">" | awk -F[\>\<] '{print $3}')

# Process first page.
process_html $current_page

# If "Next" button exists, then we continue
next=$( cat $temporal_file | awk 'match($0, /Next/)')

while [ ${#next} -ne 0 ] && [ $current_page -le $max_pages ]; do
	current_page=$((current_page+1))
	process_html $current_page
	next=$( cat $temporal_file | awk 'match($0, /Next/)')
done

# Total to logging:
total=$( cat $results_file | wc -l )
# Logging again:
echo "Query: '$query', Extracted: $total, Total: $total_shodan" >> $logging_file

# Showing data:
cat $results_file

delete_temporal_files

exit 0
