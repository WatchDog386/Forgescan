# Zeek settings for the AI-NIDR sensor. Copy to Zeek's site/ folder.
@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/dns

# Write logs as JSON, one record per line, so the collector can read them.
@load policy/tuning/json-logs

# Close the record of an unanswered connection quickly, so a scan shows up within seconds.
redef tcp_attempt_delay = 5 secs;
