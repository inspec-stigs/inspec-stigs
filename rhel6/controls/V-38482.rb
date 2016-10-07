# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38482 - The system must require passwords to contain at least one numeric character.'

control 'V-38482' do
  impact 0.1
  title 'The system must require passwords to contain at least one numeric character.'
  desc '
Requiring digits makes password guessing attacks more difficult by ensuring a larger search space.
'
  tag 'stig','V-38482'
  tag severity: 'low'
  tag checkid: 'C-46037r1_chk'
  tag fixid: 'F-43427r1_fix'
  tag version: 'RHEL-06-000056'
  tag ruleid: 'SV-50282r1_rule'
  tag fixtext: '
The pam_cracklib module\'s "dcredit" parameter controls requirements for usage of digits in a password. When set to a negative number, any password will be required to contain that many digits. When set to a positive number, pam_cracklib will grant +1 additional length credit for each digit. Add "dcredit=-1" after pam_cracklib.so to require use of a digit in passwords.
'
  tag checktext: '
To check how many digits are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

The "dcredit" parameter (as a negative number) will indicate how many digits are required. The DoD requires at least one digit in a password. This would appear as "dcredit=-1". 
If dcredit is not found or not set to the required value, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
