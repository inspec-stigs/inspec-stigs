# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38498 - Audit log files must have mode 0640 or less permissive.'

control 'V-38498' do
  impact 0.5
  title 'Audit log files must have mode 0640 or less permissive.'
  desc '
If users can write to audit logs, audit trails can be modified or destroyed.
'
  tag 'stig','V-38498'
  tag severity: 'medium'
  tag checkid: 'C-46055r1_chk'
  tag fixid: 'F-43445r1_fix'
  tag version: 'RHEL-06-000383'
  tag ruleid: 'SV-50299r1_rule'
  tag fixtext: '
Change the mode of the audit log files with the following command: 

# chmod 0640 [audit_file]
'
  tag checktext: '
Run the following command to check the mode of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a:%n

Audit logs must be mode 0640 or less permissive. 
If any are more permissive, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
