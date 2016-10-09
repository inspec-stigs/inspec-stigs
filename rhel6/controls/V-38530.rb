# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38530 - The audit system must be configured to audit all attempts to alter system time through /etc/localtime.'

control 'V-38530' do
  impact 0.1
  title 'The audit system must be configured to audit all attempts to alter system time through /etc/localtime.'
  desc '
Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.
'
  tag 'stig','V-38530'
  tag severity: 'low'
  tag checkid: 'C-46087r1_chk'
  tag fixid: 'F-43477r1_fix'
  tag version: 'RHEL-06-000173'
  tag ruleid: 'SV-50331r1_rule'
  tag fixtext: '
Add the following to "/etc/audit/audit.rules":

-w /etc/localtime -p wa -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport and should always be used.
'
  tag checktext: '
To determine if the system is configured to audit attempts to alter time via the /etc/localtime file, run the following command:

# auditctl -l | grep "watch=/etc/localtime"

If the system is configured to audit this activity, it will return a line.
If the system is not configured to audit time changes, this is a finding.
'

# START_DESCRIBE V-38530
describe auditd_rules do
  its('lines') { should include("-w /etc/localtime -p wa -k audit_time_rules") }
end
# END_DESCRIBE V-38530

end

#'exit,always watch=/etc/group perm=wa',
