# dns-rr-monitor
Runs like a hot-damn:
`
./dns_watcher.py -e you@example.com -f nobody@example.com \
                 -l /tmp/dns-rr-mon.log -m localhost \
                 -s /tmp/dns-rr-mon.store -rr example.com -t NS
`

Keeps state in the Store file, mails you when changes occur.
Run from cron as often as you'd like to monitor something.
