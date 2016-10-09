# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38572 - The system must require at least four characters be changed between the old and new passwords during a password change.'

control 'V-38572' do
  impact 0.1
  title 'The system must require at least four characters be changed between the old and new passwords during a password change.'
  desc '
Requiring a minimum number of different characters during password changes ensures that newly changed passwords should not resemble previously compromised ones. Note that passwords which are changed on compromised systems will still be compromised, however.
'
  tag 'stig','V-38572'
  tag severity: 'low'
  tag checkid: 'C-46130r1_chk'
  tag fixid: 'F-43520r1_fix'
  tag version: 'RHEL-06-000060'
  tag ruleid: 'SV-50373r1_rule'
  tag fixtext: '
The pam_cracklib module\'s "difok" parameter controls requirements for usage of different characters during a password change. Add "difok=[NUM]" after pam_cracklib.so to require differing characters when changing passwords, substituting [NUM] appropriately. The DoD requirement is 4.
'
  tag checktext: '
To check how many characters must differ during a password change, run the following command:

$ grep pam_cracklib /etc/pam.d/system-auth

The "difok" parameter will indicate how many characters must differ. The DoD requires four characters differ during a password change. This would appear as "difok=4".
If difok is not found or not set to the required value, this is a finding.
'

# START_DESCRIBE V-38572
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /pam_cracklib\.so.*?difok=[4-9]+/ }
  end
# END_DESCRIBE V-38572

end
