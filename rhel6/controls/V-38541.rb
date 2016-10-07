# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38541 - The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux).'

control 'V-38541' do
  impact 0.1
  title 'The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux).'
  desc '
The system\'s mandatory access policy (SELinux) should not be arbitrarily changed by anything other than administrator action. All changes to MAC policy should be audited.
'
  tag 'stig','V-38541'
  tag severity: 'low'
  tag checkid: 'C-46099r1_chk'
  tag fixid: 'F-43489r1_fix'
  tag version: 'RHEL-06-000183'
  tag ruleid: 'SV-50342r1_rule'
  tag fixtext: '
Add the following to "/etc/audit/audit.rules": 

-w /etc/selinux/ -p wa -k MAC-policy
'
  tag checktext: '
To determine if the system is configured to audit changes to its SELinux configuration files, run the following command: 

# auditctl -l | grep "dir=/etc/selinux"

If the system is configured to watch for changes to its SELinux configuration, a line should be returned (including "perm=wa" indicating permissions that are watched). 
If the system is not configured to audit attempts to change the MAC policy, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
