# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38693 - The system must require passwords to contain no more than three consecutive repeating characters.'

control 'V-38693' do
  impact 0.1
  title 'The system must require passwords to contain no more than three consecutive repeating characters.'
  desc '
Passwords with excessive repeating characters may be more vulnerable to password-guessing attacks.
'
  tag 'stig','V-38693'
  tag severity: 'low'
  tag checkid: 'C-46255r1_chk'
  tag fixid: 'F-43642r2_fix'
  tag version: 'RHEL-06-000299'
  tag ruleid: 'SV-50494r2_rule'
  tag fixtext: '
The pam_cracklib module\'s "maxrepeat" parameter controls requirements for consecutive repeating characters. When set to a positive number, it will reject passwords which contain more than that number of consecutive characters. Add "maxrepeat=3" after pam_cracklib.so to prevent a run of (3 + 1) or more identical characters. 

password required pam_cracklib.so maxrepeat=3 
'
  tag checktext: '
To check the maximum value for consecutive repeating characters, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

Look for the value of the "maxrepeat" parameter. The DoD requirement is 3. 
If maxrepeat is not found or not set to the required value, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
