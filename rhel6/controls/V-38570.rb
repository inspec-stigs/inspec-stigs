# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38570 - The system must require passwords to contain at least one special character.'

control 'V-38570' do
  impact 0.1
  title 'The system must require passwords to contain at least one special character.'
  desc '
Requiring a minimum number of special characters makes password guessing attacks more difficult by ensuring a larger search space.
'
  tag 'stig','V-38570'
  tag severity: 'low'
  tag checkid: 'C-46128r1_chk'
  tag fixid: 'F-43518r1_fix'
  tag version: 'RHEL-06-000058'
  tag ruleid: 'SV-50371r1_rule'
  tag fixtext: '
The pam_cracklib module\'s "ocredit=" parameter controls requirements for usage of special (or ``other\'\') characters in a password. When set to a negative number, any password will be required to contain that many special characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each special character. Add "ocredit=-1" after pam_cracklib.so to require use of a special character in passwords.
'
  tag checktext: '
To check how many special characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

The "ocredit" parameter (as a negative number) will indicate how many special characters are required. The DoD requires at least one special character in a password. This would appear as "ocredit=-1". 
If ocredit is not found or not set to the required value, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
