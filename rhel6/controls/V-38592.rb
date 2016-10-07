# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38592 - The system must require administrator action to unlock an account locked by excessive failed login attempts.'

control 'V-38592' do
  impact 0.5
  title 'The system must require administrator action to unlock an account locked by excessive failed login attempts.'
  desc '
Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks. Ensuring that an administrator is involved in unlocking locked accounts draws appropriate attention to such situations.
'
  tag 'stig','V-38592'
  tag severity: 'medium'
  tag checkid: 'C-46151r5_chk'
  tag fixid: 'F-43541r6_fix'
  tag version: 'RHEL-06-000356'
  tag ruleid: 'SV-50393r4_rule'
  tag fixtext: '
To configure the system to lock out accounts after a number of incorrect logon attempts and require an administrator to unlock the account using "pam_faillock.so", modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows: 

Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section: 

auth required pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section: 

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section: 

account required pam_faillock.so

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
'
  tag checktext: '
To ensure the failed password attempt policy is configured correctly, run the following command: 

# grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

The output should show "unlock_time=<some-large-number>"; the largest acceptable value is 604800 seconds (one week). 
If that is not the case, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
