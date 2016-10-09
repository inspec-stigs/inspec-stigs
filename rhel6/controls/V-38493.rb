# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38493 - Audit log directories must have mode 0755 or less permissive.'

control 'V-38493' do
  impact 0.5
  title 'Audit log directories must have mode 0755 or less permissive.'
  desc '
If users can delete audit logs, audit trails can be modified or destroyed.
'
  tag 'stig','V-38493'
  tag severity: 'medium'
  tag checkid: 'C-46050r1_chk'
  tag fixid: 'F-43440r1_fix'
  tag version: 'RHEL-06-000385'
  tag ruleid: 'SV-50294r1_rule'
  tag fixtext: '
Change the mode of the audit log directories with the following command:

# chmod go-w [audit_directory]
'
  tag checktext: '
Run the following command to check the mode of the system audit directories:

grep "^log_file" /etc/audit/auditd.conf|sed \'s/^[^/]*//; s/[^/]*$//\'|xargs stat -c %a:%n

Audit directories must be mode 0755 or less permissive.
If any are more permissive, this is a finding.
'

# START_DESCRIBE V-38493
  describe command('find -L /var/log/audit -perm /022') do
    its('stdout') { should eq '' }
  end
# END_DESCRIBE V-38493

end
