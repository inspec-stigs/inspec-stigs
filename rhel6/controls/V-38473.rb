# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38473 - The system must use a separate file system for user home directories.'

control 'V-38473' do
  impact 0.1
  title 'The system must use a separate file system for user home directories.'
  desc '
Ensuring that "/home" is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage.
'
  tag 'stig','V-38473','mount','home'
  tag severity: 'low'
  tag checkid: 'C-46028r1_chk'
  tag fixid: 'F-43418r1_fix'
  tag version: 'RHEL-06-000007'
  tag ruleid: 'SV-50273r1_rule'
  tag fixtext: '
If user home directories will be stored locally, create a separate partition for "/home" at installation time (or migrate it later using LVM). If "/home" will be mounted from another system such as an NFS server, then creating a separate partition is not necessary at installation time, and the mountpoint can instead be configured later.
'
  tag checktext: '
Run the following command to determine if "/home" is on its own partition or logical volume:

$ mount | grep "on /home "

If "/home" has its own partition or volume group, a line will be returned.
If no line is returned, this is a finding.
'

# START_DESCRIBE V-38473
  describe mount('/home') do
    it { should be_mounted }
  end
# END_DESCRIBE V-38473

end
