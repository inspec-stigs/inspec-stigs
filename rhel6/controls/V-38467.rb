# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38467 - The system must use a separate file system for the system audit data path.'

control 'V-38467' do
  impact 0.1
  title 'The system must use a separate file system for the system audit data path.'
  desc '
Placing "/var/log/audit" in its own partition enables better separation between audit files and other files, and helps ensure that auditing cannot be halted due to the partition running out of space.
'
  tag 'stig','V-38467'
  tag severity: 'low'
  tag checkid: 'C-46022r1_chk'
  tag fixid: 'F-43412r1_fix'
  tag version: 'RHEL-06-000004'
  tag ruleid: 'SV-50267r1_rule'
  tag fixtext: '
Audit logs are stored in the "/var/log/audit" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it later using LVM. Make absolutely certain that it is large enough to store all audit logs that will be created by the auditing daemon.
'
  tag checktext: '
Run the following command to determine if "/var/log/audit" is on its own partition or logical volume: 

$ mount | grep "on /var/log/audit "

If "/var/log/audit" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
