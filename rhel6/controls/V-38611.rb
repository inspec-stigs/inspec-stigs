# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38611 - The SSH daemon must ignore .rhosts files.'

control 'V-38611' do
  impact 0.5
  title 'The SSH daemon must ignore .rhosts files.'
  desc '
SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.
'
  tag 'stig','V-38611'
  tag severity: 'medium'
  tag checkid: 'C-46169r1_chk'
  tag fixid: 'F-43559r1_fix'
  tag version: 'RHEL-06-000234'
  tag ruleid: 'SV-50412r1_rule'
  tag fixtext: '
SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via ".rhosts" files.

To ensure this behavior is disabled, add or correct the following line in "/etc/ssh/sshd_config":

IgnoreRhosts yes
'
  tag checktext: '
To determine how the SSH daemon\'s "IgnoreRhosts" option is set, run the following command:

# grep -i IgnoreRhosts /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "yes" is returned, then the required value is set.
If the required value is not set, this is a finding.
'

# START_DESCRIBE V-38611
  tag 'sshd','IgnoreRhosts'
  describe sshd_config do
    its('IgnoreRhosts') { should eq 'yes' }
  end
# END_DESCRIBE V-38611

end
