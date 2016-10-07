# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38699 - All public directories must be owned by a system account.'

control 'V-38699' do
  impact 0.1
  title 'All public directories must be owned by a system account.'
  desc '
Allowing a user account to own a world-writable directory is undesirable because it allows the owner of that directory to remove or replace any files that may be placed in the directory by other users.
'
  tag 'stig','V-38699'
  tag severity: 'low'
  tag checkid: 'C-46260r3_chk'
  tag fixid: 'F-43648r1_fix'
  tag version: 'RHEL-06-000337'
  tag ruleid: 'SV-50500r2_rule'
  tag fixtext: '
All directories in local partitions which are world-writable should be owned by root or another system account. If any world-writable directories are not owned by a system account, this should be investigated. Following this, the files should be deleted or assigned to an appropriate group.
'
  tag checktext: '
The following command will discover and print world-writable directories that are not owned by a system account, given the assumption that only system accounts have a uid lower than 500. Run it once for each local partition [PART]: 

# find [PART] -xdev -type d -perm -0002 -uid +499 -print


If there is output, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
