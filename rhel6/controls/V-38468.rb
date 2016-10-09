# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38468 - The audit system must take appropriate action when the audit storage volume is full.'

control 'V-38468' do
  impact 0.5
  title 'The audit system must take appropriate action when the audit storage volume is full.'
  desc '
Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.
'
  tag 'stig','V-38468','audit'
  tag severity: 'medium'
  tag checkid: 'C-46023r1_chk'
  tag fixid: 'F-43413r1_fix'
  tag version: 'RHEL-06-000510'
  tag ruleid: 'SV-50268r1_rule'
  tag fixtext: '
The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately:

disk_full_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include:

"ignore"
"syslog"
"exec"
"suspend"
"single"
"halt"


Set this to "syslog", "exec", "single", or "halt".
'
  tag checktext: '
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to take appropriate action when the audit storage volume is full:

# grep disk_full_action /etc/audit/auditd.conf
disk_full_action = [ACTION]


If the system is configured to "suspend" when the volume is full or "ignore" that it is full, this is a finding.
'

# START_DESCRIBE V-38468
  describe auditd_conf do
    its('disk_full_action') { should_not cmp 'suspend' }
    its('disk_full_action') { should_not cmp 'ignore' }
  end
# END_DESCRIBE V-38468

end
