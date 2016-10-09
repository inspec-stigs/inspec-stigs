# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38569 - The system must require passwords to contain at least one uppercase alphabetic character.'

control 'V-38569' do
  impact 0.1
  title 'The system must require passwords to contain at least one uppercase alphabetic character.'
  desc '
Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space.
'
  tag 'stig','V-38569'
  tag severity: 'low'
  tag checkid: 'C-46127r1_chk'
  tag fixid: 'F-43517r1_fix'
  tag version: 'RHEL-06-000057'
  tag ruleid: 'SV-50370r1_rule'
  tag fixtext: '
The pam_cracklib module\'s "ucredit=" parameter controls requirements for usage of uppercase letters in a password. When set to a negative number, any password will be required to contain that many uppercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each uppercase character. Add "ucredit=-1" after pam_cracklib.so to require use of an uppercase character in passwords.
'
  tag checktext: '
To check how many uppercase characters are required in a password, run the following command:

$ grep pam_cracklib /etc/pam.d/system-auth

The "ucredit" parameter (as a negative number) will indicate how many uppercase characters are required. The DoD requires at least one uppercase character in a password. This would appear as "ucredit=-1".
If ucredit is not found or not set to the required value, this is a finding.
'

# START_DESCRIBE V-38569
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /pam_cracklib\.so.*?ucredit=-\d+/ }
  end
# END_DESCRIBE V-38569

end
