# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38445 - Audit log files must be group-owned by root.'

control 'V-38445' do
  impact 0.5
  title 'Audit log files must be group-owned by root.'
  desc '
If non-privileged users can write to audit logs, audit trails can be modified or destroyed.
'
  tag 'stig','V-38445'
  tag severity: 'medium'
  tag checkid: 'C-46000r1_chk'
  tag fixid: 'F-43390r1_fix'
  tag version: 'RHEL-06-000522'
  tag ruleid: 'SV-50245r2_rule'
  tag fixtext: '
Change the group owner of the audit log files with the following command: 

# chgrp root [audit_file]
'
  tag checktext: '
Run the following command to check the group owner of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %G:%n

Audit logs must be group-owned by root. 
If they are not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
