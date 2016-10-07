# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38613 - The system must not permit root logins using remote access programs such as ssh.'

control 'V-38613' do
  impact 0.5
  title 'The system must not permit root logins using remote access programs such as ssh.'
  desc '
Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root\'s password.
'
  tag 'stig','V-38613'
  tag severity: 'medium'
  tag checkid: 'C-46171r1_chk'
  tag fixid: 'F-43561r1_fix'
  tag version: 'RHEL-06-000237'
  tag ruleid: 'SV-50414r1_rule'
  tag fixtext: '
The root user should never be allowed to log in to a system directly over a network. To disable root login via SSH, add or correct the following line in "/etc/ssh/sshd_config": 

PermitRootLogin no
'
  tag checktext: '
To determine how the SSH daemon\'s "PermitRootLogin" option is set, run the following command: 

# grep -i PermitRootLogin /etc/ssh/sshd_config

If a line indicating "no" is returned, then the required value is set. 
If the required value is not set, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
