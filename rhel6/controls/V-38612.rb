# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38612 - The SSH daemon must not allow host-based authentication.'

control 'V-38612' do
  impact 0.5
  title 'The SSH daemon must not allow host-based authentication.'
  desc '
SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.
'
  tag 'stig','V-38612'
  tag severity: 'medium'
  tag checkid: 'C-46170r1_chk'
  tag fixid: 'F-43560r1_fix'
  tag version: 'RHEL-06-000236'
  tag ruleid: 'SV-50413r1_rule'
  tag fixtext: '
SSH\'s cryptographic host-based authentication is more secure than ".rhosts" authentication, since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization.

To disable host-based authentication, add or correct the following line in "/etc/ssh/sshd_config":

HostbasedAuthentication no
'
  tag checktext: '
To determine how the SSH daemon\'s "HostbasedAuthentication" option is set, run the following command:

# grep -i HostbasedAuthentication /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set.
If the required value is not set, this is a finding.
'

# START_DESCRIBE V-38612
  tag 'sshd','HostbasedAuthentication'
  describe sshd_config do
    its('HostbasedAuthentication') { should eq 'no' }
  end
# END_DESCRIBE V-38612

end
