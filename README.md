# check_rbl

Nagios plugin to check if a mail server IP is listed on major blacklists

Parameters: IP or hostname of mailserver
Return: 0/1/2/3 for OK/warn/crit/unknown with line of text for logs

DO NOT call this plugin more often than once an hour as it can overload the
servers and cause you to be blocked.

Use the `-z` option for Zabbix mode (non-HTML and always zero exit status).  Zabbix users can check for the string *LISTED* in their triggers.
