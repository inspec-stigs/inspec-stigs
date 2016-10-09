# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38636 - The system must retain enough rotated audit logs to cover the required log retention period.'

control 'V-38636' do
  impact 0.5
  title 'The system must retain enough rotated audit logs to cover the required log retention period.'
  desc '
The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.
'
  tag 'stig','V-38636'
  tag severity: 'medium'
  tag checkid: 'C-46195r1_chk'
  tag fixid: 'F-43585r1_fix'
  tag version: 'RHEL-06-000159'
  tag ruleid: 'SV-50437r1_rule'
  tag fixtext: '
Determine how many log files "auditd" should retain when it rotates logs. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [NUMLOGS] with the correct value:

num_logs = [NUMLOGS]

Set the value to 5 for general-purpose systems. Note that values less than 2 result in no log rotation.
'
  tag checktext: '
Inspect "/etc/audit/auditd.conf" and locate the following line to determine how many logs the system is configured to retain after rotation: "# grep num_logs /etc/audit/auditd.conf"

num_logs = 5


If the overall system log file(s) retention hasn\'t been properly set up, this is a finding.
'

# START_DESCRIBE V-38636
  tag 'auditd','auditd.conf','num_logs'
  describe parse_config_file("/etc/audit/auditd.conf") do
    its("num_logs") { should cmp '5' }
  end
# END_DESCRIBE V-38636

end
