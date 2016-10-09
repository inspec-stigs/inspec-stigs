# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38634 - The system must rotate audit log files that reach the maximum file size.'

control 'V-38634' do
  impact 0.5
  title 'The system must rotate audit log files that reach the maximum file size.'
  desc '
Automatically rotating logs (by setting this to "rotate") minimizes the chances of the system unexpectedly running out of disk space by being overwhelmed with log data. However, for systems that must never discard log data, or which use external processes to transfer it and reclaim space, "keep_logs" can be employed.
'
  tag 'stig','V-38634'
  tag severity: 'medium'
  tag checkid: 'C-46193r3_chk'
  tag fixid: 'F-43583r1_fix'
  tag version: 'RHEL-06-000161'
  tag ruleid: 'SV-50435r2_rule'
  tag fixtext: '
The default action to take when the logs reach their maximum size is to rotate the log files, discarding the oldest one. To configure the action taken by "auditd", add or correct the line in "/etc/audit/auditd.conf":

max_log_file_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include:

"ignore"
"syslog"
"suspend"
"rotate"
"keep_logs"


Set the "[ACTION]" to "rotate" to ensure log rotation occurs. This is the default. The setting is case-insensitive.
'
  tag checktext: '
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to rotate logs when they reach their maximum size:

# grep max_log_file_action /etc/audit/auditd.conf
max_log_file_action = rotate

If the "keep_logs" option is configured for the "max_log_file_action" line in "/etc/audit/auditd.conf" and an alternate process is in place to ensure audit data does not overwhelm local audit storage, this is not a finding.

If the system has not been properly set up to rotate audit logs, this is a finding.
'

# START_DESCRIBE V-38634
  tag 'auditd','auditd.conf','max_log_file_action'
  describe parse_config_file("/etc/audit/auditd.conf") do
    its("max_log_file_action") { should cmp 'rotate' }
  end
# END_DESCRIBE V-38634

end
