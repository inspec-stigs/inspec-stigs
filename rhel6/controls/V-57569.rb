# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-57569 - The noexec option must be added to the /tmp partition.'

control 'V-57569' do
  impact 0.5
  title 'The noexec option must be added to the /tmp partition.'
  desc '
Allowing users to execute binaries from world-writable directories such as "/tmp" should never be necessary in normal operation and can expose the system to potential compromise.
'
  tag 'stig','V-57569'
  tag severity: 'medium'
  tag checkid: 'C-58279r1_chk'
  tag fixid: 'F-62639r1_fix'
  tag version: 'RHEL-06-000528'
  tag ruleid: 'SV-71919r1_rule'
  tag fixtext: '
The "noexec" mount option can be used to prevent binaries from being executed out of "/tmp". Add the "noexec" option to the fourth column of "/etc/fstab" for the line which controls mounting of "/tmp".
'
  tag checktext: '
To verify that binaries cannot be directly executed from the /tmp directory, run the following command:

$ grep \'\s/tmp\' /etc/fstab

The resulting output will show whether the /tmp partition has the "noexec" flag set. If the /tmp partition does not have the noexec flag set, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
