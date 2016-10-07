# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38615 - The SSH daemon must be configured with the Department of Defense (DoD) login banner.'

control 'V-38615' do
  impact 0.5
  title 'The SSH daemon must be configured with the Department of Defense (DoD) login banner.'
  desc '
The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.
'
  tag 'stig','V-38615'
  tag severity: 'medium'
  tag checkid: 'C-46173r1_chk'
  tag fixid: 'F-43563r1_fix'
  tag version: 'RHEL-06-000240'
  tag ruleid: 'SV-50416r1_rule'
  tag fixtext: '
To enable the warning banner and ensure it is consistent across the system, add or correct the following line in "/etc/ssh/sshd_config": 

Banner /etc/issue

Another section contains information on how to create an appropriate system-wide warning banner.
'
  tag checktext: '
To determine how the SSH daemon\'s "Banner" option is set, run the following command: 

# grep -i Banner /etc/ssh/sshd_config

If a line indicating /etc/issue is returned, then the required value is set. 
If the required value is not set, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
