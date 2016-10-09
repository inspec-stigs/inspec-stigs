# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38585 - The system boot loader must require authentication.'

control 'V-38585' do
  impact 0.5
  title 'The system boot loader must require authentication.'
  desc '
Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode.
'
  tag 'stig','V-38585'
  tag severity: 'medium'
  tag checkid: 'C-46143r2_chk'
  tag fixid: 'F-43533r1_fix'
  tag version: 'RHEL-06-000068'
  tag ruleid: 'SV-50386r2_rule'
  tag fixtext: '
The grub boot loader should have password protection enabled to protect boot-time settings. To do so, select a password and then generate a hash from it by running the following command:

# grub-crypt --sha-512

When prompted to enter a password, insert the following line into "/etc/grub.conf" immediately after the header comments. (Use the output from "grub-crypt" as the value of [password-hash]):

password --encrypted [password-hash]
'
  tag checktext: '
To verify the boot loader password has been set and encrypted, run the following command:

# grep password /etc/grub.conf

The output should show the following:

password --encrypted $6$[rest-of-the-password-hash]

If it does not, this is a finding.
'

# START_DESCRIBE V-38585
  describe file('/etc/grub.conf') do
    its('content') { should match '^password --encrypted .*$' }
  end

# END_DESCRIBE V-38585

end
