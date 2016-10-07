# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38581 - The system boot loader configuration file(s) must be group-owned by root.'

control 'V-38581' do
  impact 0.5
  title 'The system boot loader configuration file(s) must be group-owned by root.'
  desc '
The "root" group is a highly-privileged group. Furthermore, the group-owner of this file should not have any access privileges anyway.
'
  tag 'stig','V-38581'
  tag severity: 'medium'
  tag checkid: 'C-46139r1_chk'
  tag fixid: 'F-43529r1_fix'
  tag version: 'RHEL-06-000066'
  tag ruleid: 'SV-50382r1_rule'
  tag fixtext: '
The file "/etc/grub.conf" should be group-owned by the "root" group to prevent destruction or modification of the file. To properly set the group owner of "/etc/grub.conf", run the command: 

# chgrp root /etc/grub.conf
'
  tag checktext: '
To check the group ownership of "/etc/grub.conf", run the command: 

$ ls -lL /etc/grub.conf

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
