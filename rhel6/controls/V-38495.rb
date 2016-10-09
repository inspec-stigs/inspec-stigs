# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38495 - Audit log files must be owned by root.'

control 'V-38495' do
  impact 0.5
  title 'Audit log files must be owned by root.'
  desc '
If non-privileged users can write to audit logs, audit trails can be modified or destroyed.
'
  tag 'stig','V-38495'
  tag severity: 'medium'
  tag checkid: 'C-46053r1_chk'
  tag fixid: 'F-43443r1_fix'
  tag version: 'RHEL-06-000384'
  tag ruleid: 'SV-50296r1_rule'
  tag fixtext: '
Change the owner of the audit log files with the following command:

# chown root [audit_file]
'
  tag checktext: '
Run the following command to check the owner of the system audit logs:

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %U:%n

Audit logs must be owned by root.
If they are not, this is a finding.
'

# START_DESCRIBE V-38495
  Dir['/var/log/audit/*'].each do |log|
    describe file(log) do
      its('owner') { should eq 'root' }
    end
  end
# END_DESCRIBE V-38495

end
