# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38583 - The system boot loader configuration file(s) must have mode 0600 or less permissive.'

control 'V-38583' do
  impact 0.5
  title 'The system boot loader configuration file(s) must have mode 0600 or less permissive.'
  desc '
Proper permissions ensure that only the root user can modify important boot parameters.
'
  tag 'stig','V-38583'
  tag severity: 'medium'
  tag checkid: 'C-46141r2_chk'
  tag fixid: 'F-43531r2_fix'
  tag version: 'RHEL-06-000067'
  tag ruleid: 'SV-50384r2_rule'
  tag fixtext: '
File permissions for "/boot/grub/grub.conf" should be set to 600, which is the default. To properly set the permissions of "/boot/grub/grub.conf", run the command:

# chmod 600 /boot/grub/grub.conf

Boot partitions based on VFAT, NTFS, or other non-standard configurations may require alternative measures.
'
  tag checktext: '
To check the permissions of /etc/grub.conf, run the command:

$ sudo ls -lL /etc/grub.conf

If properly configured, the output should indicate the following permissions: "-rw-------"
If it does not, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
