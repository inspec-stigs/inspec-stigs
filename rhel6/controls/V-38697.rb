# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38697 - The sticky bit must be set on all public directories.'

control 'V-38697' do
  impact 0.1
  title 'The sticky bit must be set on all public directories.'
  desc '
Failing to set the sticky bit on public directories allows unauthorized users to delete files in the directory structure. 

The only authorized public directories are those temporary directories supplied with the system, or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system, and by users for temporary file storage - such as /tmp - and for directories requiring global read/write access.
'
  tag 'stig','V-38697'
  tag severity: 'low'
  tag checkid: 'C-46259r4_chk'
  tag fixid: 'F-43646r1_fix'
  tag version: 'RHEL-06-000336'
  tag ruleid: 'SV-50498r2_rule'
  tag fixtext: '
When the so-called \'sticky bit\' is set on a directory, only the owner of a given file may remove that file from the directory. Without the sticky bit, any user with write access to a directory may remove any file in the directory. Setting the sticky bit prevents users from removing each other\'s files. In cases where there is no reason for a directory to be world-writable, a better solution is to remove that permission rather than to set the sticky bit. However, if a directory is used by a particular application, consult that application\'s documentation instead of blindly changing modes. 
To set the sticky bit on a world-writable directory [DIR], run the following command: 

# chmod +t [DIR]
'
  tag checktext: '
To find world-writable directories that lack the sticky bit, run the following command for each local partition [PART]: 

# find [PART] -xdev -type d -perm -002 \! -perm -1000


If any world-writable directories are missing the sticky bit, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
