# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38456 - The system must use a separate file system for /var.'

control 'V-38456' do
  impact 0.1
  title 'The system must use a separate file system for /var.'
  desc '
Ensuring that "/var" is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs which use it. It is not uncommon for the "/var" directory to contain world-writable directories, installed by other software packages.
'
  tag 'stig','V-38456','mount','var'
  tag severity: 'low'
  tag checkid: 'C-46011r2_chk'
  tag fixid: 'F-43401r2_fix'
  tag version: 'RHEL-06-000002'
  tag ruleid: 'SV-50256r1_rule'
  tag fixtext: '
The "/var" directory is used by daemons and other system services to store frequently-changing data. Ensure that "/var" has its own partition or logical volume at installation time, or migrate it using LVM.
'
  tag checktext: '
Run the following command to determine if "/var" is on its own partition or logical volume:

$ mount | grep "on /var "

If "/var" has its own partition or volume group, a line will be returned.
If no line is returned, this is a finding.
'

# START_DESCRIBE V-38456
  describe mount('/var') do
    it { should be_mounted }
  end
# END_DESCRIBE V-38456

end
