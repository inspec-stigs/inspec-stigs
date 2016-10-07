# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38503 - The /etc/shadow file must be group-owned by root.'

control 'V-38503' do
  impact 0.5
  title 'The /etc/shadow file must be group-owned by root.'
  desc '
The "/etc/shadow" file stores password hashes. Protection of this file is critical for system security.
'
  tag 'stig','V-38503'
  tag severity: 'medium'
  tag checkid: 'C-46060r1_chk'
  tag fixid: 'F-43450r1_fix'
  tag version: 'RHEL-06-000034'
  tag ruleid: 'SV-50304r1_rule'
  tag fixtext: '
To properly set the group owner of "/etc/shadow", run the command: 

# chgrp root /etc/shadow
'
  tag checktext: '
To check the group ownership of "/etc/shadow", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
